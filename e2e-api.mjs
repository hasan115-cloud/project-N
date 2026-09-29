// End-to-end API test. Usage:  BASE=http://localhost:3100 node scripts/e2e-api.mjs
// Runs against a REAL server + REAL Postgres (no mocks). Leaves data behind, so
// point it at a scratch database, never production.
import assert from "node:assert/strict";
import crypto from "node:crypto";

const BASE = process.env.BASE || "http://localhost:3100";
let pass = 0;
const step = async (name, fn) => {
  try { await fn(); pass++; console.log("  ok  -", name); }
  catch (e) { console.error("  FAIL-", name, "\n      ", e.message); process.exitCode = 1; }
};

const rnd = () => crypto.randomBytes(24).toString("hex");
const mkClient = () => ({ id: "pg-client-" + rnd().slice(0, 12), secret: rnd() + rnd() });
const call = async (method, path, { body, client, headers = {} } = {}) => {
  const h = { ...headers };
  if (body !== undefined) h["Content-Type"] = "application/json";
  if (client) { h["X-Client-ID"] = client.id; h["Authorization"] = "Bearer " + client.secret; }
  const res = await fetch(BASE + "/api" + path, { method, headers: h, body: body === undefined ? undefined : (typeof body === "string" ? body : JSON.stringify(body)) });
  let json = null; try { json = await res.json(); } catch {}
  return { status: res.status, json };
};
const register = (c, name) => call("POST", "/clients/register", {
  body: { clientId: c.id, clientName: name, os: "Windows", browser: "Chrome 130", platform: "Win32", extensionVersion: "1.5" },
  headers: { Authorization: "Bearer " + c.secret }
});
const uid = () => crypto.randomUUID();

const A = mkClient(), B = mkClient();
const tag = rnd().slice(0, 6);
const badDomain = `evil-${tag}.xyz`;

console.log("== registration & identity");
await step("health reports DB up + schema version", async () => {
  const r = await call("GET", "/health"); assert.equal(r.status, 200); assert.equal(r.json.database, "up"); assert.equal(r.json.schemaVersion, "2");
});
await step("register system A", async () => { const r = await register(A, "Computer-A"); assert.equal(r.status, 200); assert.equal(r.json.client.id, A.id); });
await step("re-register A 5x concurrently -> still ONE system (no duplicates)", async () => {
  await Promise.all([1,2,3,4,5].map(() => register(A, "Computer-A")));
  const list = (await call("GET", "/clients")).json.clients.filter(c => c.id === A.id);
  assert.equal(list.length, 1);
});
await step("same id with a DIFFERENT secret is refused (no hijack)", async () => {
  const r = await register({ id: A.id, secret: rnd() + rnd() }, "Attacker"); assert.equal(r.status, 401); assert.equal(r.json.code, "id_taken");
});
await step("register rejects short secret / bad id", async () => {
  assert.equal((await register({ id: A.id, secret: "short" }, "x")).status, 401);
  assert.equal((await register({ id: "no", secret: rnd() + rnd() }, "x")).status, 400);
});
await step("extension endpoints reject missing / wrong credentials", async () => {
  assert.equal((await call("POST", "/scan", { body: { url: "https://example.com" } })).status, 401);
  assert.equal((await call("POST", "/scan", { body: { url: "https://example.com" }, client: { id: A.id, secret: rnd() + rnd() } })).status, 401);
  assert.equal((await call("GET", "/extension/rules")).status, 401);
});
await step("register system B; both systems listed separately", async () => {
  assert.equal((await register(B, "Computer-B")).status, 200);
  const ids = (await call("GET", "/clients")).json.clients.map(c => c.id);
  assert.ok(ids.includes(A.id) && ids.includes(B.id));
});
await step("A cannot act as B (id from header + A's secret)", async () => {
  const r = await call("POST", "/scan", { body: { url: "https://example.com" }, client: { id: B.id, secret: A.secret } });
  assert.equal(r.status, 401);
});

console.log("== rules (dashboard -> Supabase -> extension)");
let v0, phishRule, wlRule;
await step("initial rules version readable", async () => { v0 = (await call("GET", "/rules")).json.version; assert.equal(typeof v0, "number"); });
await step("add phishing rule (URL form is normalized)", async () => {
  const r = await call("POST", "/rules/phishing", { body: { pattern: `https://www.${badDomain.toUpperCase()}/`, severity: "CRITICAL", reason: "Credential harvester" } });
  assert.equal(r.status, 201); phishRule = r.json.rule; assert.equal(phishRule.pattern, badDomain); assert.equal(phishRule.enabled, true);
});
await step("duplicate rule -> 409", async () => { assert.equal((await call("POST", "/rules/phishing", { body: { pattern: badDomain } })).status, 409); });
await step("invalid / over-broad patterns -> 400", async () => {
  for (const p of ["com", "", "a b.com", "ex*mple.com", 5]) assert.equal((await call("POST", "/rules/phishing", { body: { pattern: p } })).status, 400, String(p));
  assert.equal((await call("POST", "/rules/phishing", { body: "not json{" })).status, 400);
});
await step("rules survive: fresh GET returns the rule; version bumped", async () => {
  const r = (await call("GET", "/rules")).json; assert.ok(r.phishing.some(x => x.id === phishRule.id)); assert.ok(r.version > v0);
});
await step("extension rule sync: changed=true with rule, changed=false when current", async () => {
  const first = await call("GET", "/extension/rules?since=" + v0, { client: A });
  assert.equal(first.json.changed, true); assert.ok(first.json.phishing.some(x => x.pattern === badDomain));
  const again = await call("GET", "/extension/rules?since=" + first.json.version, { client: A });
  assert.equal(again.json.changed, false);
});
await step("add whitelist rule", async () => {
  const r = await call("POST", "/rules/whitelist", { body: { pattern: `docs.${badDomain}`, description: "internal docs" } });
  assert.equal(r.status, 201); wlRule = r.json.rule;
});

console.log("== scanning, matching & history");
const ev1 = uid();
await step("scan URL matching phishing rule -> BLOCKED + matched rule reported + recorded", async () => {
  const r = await call("POST", "/scan", { client: A, body: { url: `https://login.${badDomain}/verify?x=1`, source: "extension-navigation", eventId: ev1 } });
  assert.equal(r.status, 200); assert.equal(r.json.action, "BLOCKED"); assert.equal(r.json.verdict, "PHISHING");
  assert.equal(r.json.ruleTriggered, true); assert.equal(r.json.ruleType, "PHISHING"); assert.equal(r.json.matchedRule.pattern, badDomain);
  assert.equal(r.json.recorded, true);
});
await step("history has exactly that URL with rule fields", async () => {
  const h = (await call("GET", `/events?clientId=${A.id}`)).json;
  const e = h.events.filter(x => x.eventId === ev1); assert.equal(e.length, 1);
  assert.equal(e[0].url, `https://login.${badDomain}/verify?x=1`); assert.equal(e[0].ruleTriggered, true);
  assert.equal(e[0].ruleType, "PHISHING"); assert.equal(e[0].matchedPattern, badDomain); assert.equal(e[0].matchedRuleId, phishRule.id);
  assert.equal(e[0].verdict, "BLOCKED"); assert.equal(e[0].decisionSource, "rule");
});
await step("exactly ONE alert created, carrying the matched rule", async () => {
  const a = (await call("GET", `/threats?clientId=${A.id}`)).json.alerts.filter(x => x.eventId === ev1);
  assert.equal(a.length, 1); assert.equal(a[0].matchedPattern, badDomain); assert.equal(a[0].ruleType, "PHISHING"); assert.equal(a[0].status, "ACTIVE");
});
await step("replaying the same eventId does NOT duplicate history or alert", async () => {
  const r = await call("POST", "/scan", { client: A, body: { url: `https://login.${badDomain}/verify?x=1`, eventId: ev1 } });
  assert.equal(r.json.duplicate, true);
  const batch = await call("POST", "/url-events", { client: A, body: { events: [{ eventId: ev1, url: `https://login.${badDomain}/verify?x=1` }] } });
  assert.equal(batch.json.duplicates, 1); assert.equal(batch.json.accepted, 0);
  assert.equal((await call("GET", `/events?clientId=${A.id}`)).json.events.filter(x => x.eventId === ev1).length, 1);
  assert.equal((await call("GET", `/threats?clientId=${A.id}`)).json.alerts.filter(x => x.eventId === ev1).length, 1);
});
await step("more-specific whitelist beats broader block (precedence)", async () => {
  const r = await call("POST", "/scan", { client: A, body: { url: `https://docs.${badDomain}/guide`, eventId: uid() } });
  assert.equal(r.json.action, "ALLOWED"); assert.equal(r.json.ruleType, "WHITELIST"); assert.equal(r.json.matchedRule.pattern, `docs.${badDomain}`);
});
await step("substring bypass no longer works (evil URL containing a whitelisted name)", async () => {
  const r = await call("POST", "/scan", { client: A, body: { url: `https://attacker-${tag}.xyz/docs.${badDomain}`, eventId: uid() } });
  assert.notEqual(r.json.ruleType, "WHITELIST");
});
await step("batch ingest: accepted / duplicate / internal-host ignored / invalid all accounted for", async () => {
  const good = uid();
  const r = await call("POST", "/url-events", { client: A, body: { events: [
    { eventId: good, url: "https://example.org/page", source: "extension-navigation", observedAt: new Date(Date.now() - 60000).toISOString() },
    { eventId: ev1, url: `https://login.${badDomain}/verify?x=1` },
    { eventId: uid(), url: "https://abcdefgh.supabase.co/rest/v1/x" },
    { eventId: uid(), url: "javascript:alert(1)" },
    { url: "https://no-event-id.com" }
  ] } });
  assert.equal(r.status, 200); assert.equal(r.json.accepted, 1); assert.equal(r.json.duplicates, 1); assert.equal(r.json.ignored, 1); assert.equal(r.json.invalid, 2);
  assert.ok(r.json.acknowledgedIds.includes(good));
  const h = (await call("GET", `/events?clientId=${A.id}&search=example.org`)).json;
  assert.equal(h.events.filter(x => x.eventId === good).length, 1);
  assert.equal(h.events.filter(x => x.url.includes("supabase.co")).length, 0);
});
await step("PAST observedAt honoured; future/absurd timestamp clamped to now", async () => {
  const past = uid(), future = uid();
  await call("POST", "/url-events", { client: A, body: { events: [
    { eventId: past, url: "https://past-visit.example.net/", observedAt: new Date(Date.now() - 3600_000).toISOString() },
    { eventId: future, url: "https://future-visit.example.net/", observedAt: new Date(Date.now() + 86400_000 * 30).toISOString() }
  ] } });
  const evs = (await call("GET", `/events?clientId=${A.id}&search=visit.example.net`)).json.events;
  const p = evs.find(e => e.eventId === past), f = evs.find(e => e.eventId === future);
  assert.ok(Date.now() - new Date(p.timestamp).getTime() > 3000_000);
  assert.ok(new Date(f.timestamp).getTime() <= Date.now() + 1000);
});
await step("bulk-scan classifies but does NOT write to URL History", async () => {
  const before = (await call("GET", `/events?clientId=${A.id}`)).json.total;
  const r = await call("POST", "/bulk-scan", { client: A, body: { urls: [`https://x.${badDomain}/a`, "https://example.com/z", "nope"] } });
  assert.equal(r.status, 200); assert.equal(r.json.results[0].action, "BLOCKED"); assert.equal(r.json.results[2].verdict, "ERROR");
  assert.equal((await call("GET", `/events?clientId=${A.id}`)).json.total, before);
});
await step("dashboard/API/self URLs are never recorded", async () => {
  const before = (await call("GET", `/events?clientId=${A.id}`)).json.total;
  const r = await call("POST", "/scan", { client: A, body: { url: "https://phishguard-test.example.app/", eventId: uid() } });
  assert.equal(r.json.ignored, true); assert.equal((await call("GET", `/events?clientId=${A.id}`)).json.total, before);
});
await step("malformed URL -> 400; oversized batch -> 400", async () => {
  assert.equal((await call("POST", "/scan", { client: A, body: { url: "::::" } })).status, 400);
  assert.equal((await call("POST", "/url-events", { client: A, body: { events: Array.from({ length: 201 }, () => ({ eventId: uid(), url: "https://a.com" })) } })).status, 400);
});

console.log("== multiple systems: isolation and totals");
await step("B scans; A and B histories are separate; totals are the SUM of real rows", async () => {
  for (let i = 0; i < 3; i++) await call("POST", "/scan", { client: B, body: { url: `https://site${i}-${tag}.example.com/`, eventId: uid() } });
  await call("POST", "/scan", { client: B, body: { url: `https://${badDomain}/`, eventId: uid() } });
  const a = (await call("GET", `/events?clientId=${A.id}`)).json, b = (await call("GET", `/events?clientId=${B.id}`)).json;
  assert.ok(a.events.every(e => e.clientId === A.id)); assert.ok(b.events.every(e => e.clientId === B.id)); assert.equal(b.total, 4);
  const stats = (await call("GET", "/stats")).json, sa = (await call("GET", `/stats?clientId=${A.id}`)).json, sb = (await call("GET", `/stats?clientId=${B.id}`)).json;
  const all = (await call("GET", "/events?limit=1")).json.total;
  assert.equal(stats.urlsMonitored, all);
  const rep = (await call("GET", "/reports")).json;
  assert.equal(rep.perSystem.reduce((n, s) => n + s.totalScanned, 0), all); // fleet total == sum of per-system rows
  const ra = rep.perSystem.find(s => s.clientId === A.id), rb = rep.perSystem.find(s => s.clientId === B.id);
  assert.equal(ra.totalScanned, sa.urlsMonitored); assert.equal(rb.totalScanned, 4); assert.equal(rb.phishing, 1);
  assert.equal(rep.summary.totalEvaluated, all);
  const cl = (await call("GET", "/clients")).json.clients; assert.equal(cl.find(c => c.id === B.id).telemetryStats.totalScanned, 4);
});
await step("same eventId used by two DIFFERENT systems does not collide", async () => {
  const shared = uid();
  const ra = await call("POST", "/scan", { client: A, body: { url: "https://shared-a.example.com/", eventId: shared } });
  const rb = await call("POST", "/scan", { client: B, body: { url: "https://shared-b.example.com/", eventId: shared } });
  assert.equal(ra.json.duplicate, false); assert.equal(rb.json.duplicate, false);
});
await step("heartbeat updates last_seen and returns only a rules VERSION", async () => {
  const r = await call("POST", "/clients/heartbeat", { client: B, body: { stats: { total: 5, phishing: 1 }, extensionVersion: "1.5" } });
  assert.equal(r.status, 200); assert.equal(typeof r.json.rulesVersion, "number"); assert.equal(r.json.rules, undefined);
});

console.log("== rule edit / disable / delete");
await step("disable rule -> removed from extension rules, no longer blocks", async () => {
  const r = await call("PATCH", `/rules/phishing/${phishRule.id}`, { body: { enabled: false } }); assert.equal(r.status, 200); assert.equal(r.json.rule.enabled, false);
  const ext = (await call("GET", "/extension/rules", { client: A })).json; assert.ok(!ext.phishing.some(x => x.id === phishRule.id));
  const s = await call("POST", "/scan", { client: A, body: { url: `https://${badDomain}/`, eventId: uid() } }); assert.notEqual(s.json.action, "BLOCKED");
  assert.ok((await call("GET", "/rules")).json.phishing.some(x => x.id === phishRule.id)); // still visible in dashboard
});
await step("re-enable + edit pattern/reason", async () => {
  const np = `renamed-${tag}.xyz`;
  const r = await call("PUT", `/rules/phishing/${phishRule.id}`, { body: { enabled: true, pattern: np, reason: "Updated reason", severity: "HIGH" } });
  assert.equal(r.status, 200); assert.equal(r.json.rule.pattern, np); assert.equal(r.json.rule.reason, "Updated reason");
  assert.equal((await call("POST", "/scan", { client: A, body: { url: `https://${np}/`, eventId: uid() } })).json.action, "BLOCKED");
  assert.equal((await call("PATCH", `/rules/phishing/${phishRule.id}`, { body: { pattern: "bad pattern" } })).status, 400);
  assert.equal((await call("PATCH", `/rules/phishing/nope`, { body: { enabled: true } })).status, 404);
});
await step("delete rule; history that referenced it is retained", async () => {
  assert.equal((await call("DELETE", `/rules/phishing/${phishRule.id}`)).status, 200);
  assert.ok(!(await call("GET", "/rules")).json.phishing.some(x => x.id === phishRule.id));
  assert.ok((await call("GET", `/events?clientId=${A.id}&search=login.${badDomain}`)).json.events.length >= 1);
  assert.equal((await call("DELETE", `/rules/phishing/${phishRule.id}`)).status, 404);
});

console.log("== pagination & alerts");
await step("history pagination is stable and complete", async () => {
  const C = mkClient(); await register(C, "Bulk");
  const events = Array.from({ length: 200 }, (_, i) => ({ eventId: uid(), url: `https://bulk${i}.example.org/p`, observedAt: new Date(Date.now() - i * 1000).toISOString() }));
  await call("POST", "/url-events", { client: C, body: { events } });
  await call("POST", "/url-events", { client: C, body: { events: events.slice(0, 50).map(e => ({ ...e, eventId: uid(), url: e.url + "2" })) } });
  const p1 = (await call("GET", `/events?clientId=${C.id}&limit=100&offset=0`)).json, p2 = (await call("GET", `/events?clientId=${C.id}&limit=100&offset=100`)).json, p3 = (await call("GET", `/events?clientId=${C.id}&limit=100&offset=200`)).json;
  assert.equal(p1.total, 250); assert.equal(p1.hasMore, true); assert.equal(p3.hasMore, false);
  const ids = new Set([...p1.events, ...p2.events, ...p3.events].map(e => e.id)); assert.equal(ids.size, 250);
  const capped = (await call("GET", `/events?clientId=${C.id}&limit=99999`)).json; assert.ok(capped.events.length <= 1000);
  assert.equal((await call("GET", "/events?classification=BOGUS")).status, 400);
});
await step("search treats % and _ literally", async () => {
  const r = (await call("GET", "/events?search=%25")).json; assert.equal(r.events.filter(e => !JSON.stringify(e).includes("%")).length, 0);
});
await step("alert lifecycle (acknowledge/resolve) persisted", async () => {
  const al = (await call("GET", `/threats?clientId=${A.id}`)).json.alerts[0];
  assert.equal((await call("PATCH", `/threats/${al.id}`, { body: { status: "ACKNOWLEDGED" } })).status, 200);
  assert.equal((await call("GET", `/threats?clientId=${A.id}`)).json.alerts.find(x => x.id === al.id).status, "ACKNOWLEDGED");
  assert.equal((await call("PATCH", `/threats/${al.id}`, { body: { status: "BOGUS" } })).status, 400);
});
await step("in-page click alert is idempotent per eventId", async () => {
  const id = "click-" + uid();
  const a = await call("POST", "/threats/alert", { client: A, body: { url: `https://${tag}-click.xyz/x`, eventId: id, score: 0.8, reasons: ["In-page phishing link click blocked"], source: "in-page-click" } });
  const b = await call("POST", "/threats/alert", { client: A, body: { url: `https://${tag}-click.xyz/x`, eventId: id } });
  assert.equal(a.json.wasNew, true); assert.equal(b.json.wasNew, false);
});

console.log("== unenroll");
await step("deleting a system removes its history + alerts (FK cascade); others untouched", async () => {
  const bBefore = (await call("GET", `/events?clientId=${B.id}`)).json.total;
  assert.equal((await call("DELETE", `/clients/${A.id}`)).status, 200);
  assert.equal((await call("GET", `/events?clientId=${A.id}`)).json.total, 0);
  assert.equal((await call("GET", `/events?clientId=${B.id}`)).json.total, bBefore);
  assert.equal((await call("POST", "/scan", { client: A, body: { url: "https://example.com" } })).status, 401);
  assert.equal((await call("DELETE", `/clients/${A.id}`)).status, 404);
});

console.log(`\n${pass} checks passed${process.exitCode ? " — WITH FAILURES" : ""}`);
