// Runs the REAL extension/background.js (+ pg-core.js) inside a Node vm with a faithful
// chrome.* API shim, talking to a REAL PhishGuard server and REAL PostgreSQL.
//
//   BASE=http://localhost:3100 node scripts/e2e-extension.mjs
//
// Server must be started with PRODUCTION_API_URL=https://phishguard-test.example.app
// (the shim rewrites that https origin to BASE, because the extension refuses http/localhost).
//
// What this does NOT prove: that real Chrome loads the manifest, plays the audio, or renders the
// toast. Those are covered by the manual checklist in DEPLOYMENT.md.
import vm from "node:vm";
import fs from "node:fs";
import path from "node:path";
import assert from "node:assert/strict";
import { webcrypto, randomUUID } from "node:crypto";

const BASE = process.env.BASE || "http://localhost:3100";
const ORIGIN = "https://phishguard-test.example.app";
const EXT = path.resolve(process.cwd(), "extension");
const realFetch = globalThis.fetch;

let pass = 0;
const step = async (name, fn) => {
  try { await fn(); pass++; console.log("  ok  -", name); }
  catch (e) { console.error("  FAIL-", name, "\n      ", e.message.split("\n").join("\n       ")); process.exitCode = 1; }
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const until = async (fn, ms = 6000, what = "condition") => {
  const t0 = Date.now();
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) throw new Error("timed out waiting for " + what); await sleep(60); }
};

// ── dashboard-side API helper (what an admin's browser does) ────────────────
const dash = async (method, p, body) => {
  const r = await realFetch(BASE + "/api" + p, { method, headers: body ? { "Content-Type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json().catch(() => null) };
};

// ── Web Locks shim (same semantics the extension relies on) ─────────────────
function makeLocks() {
  const tails = new Map(), held = new Set();
  return {
    async request(name, opts, cb) {
      if (typeof opts === "function") { cb = opts; opts = {}; }
      if (opts?.ifAvailable) { if (held.has(name)) return cb(null); held.add(name); try { return await cb({ name }); } finally { held.delete(name); } }
      const prev = tails.get(name) || Promise.resolve();
      let release; const mine = new Promise(r => (release = r));
      tails.set(name, prev.then(() => mine));
      await prev; held.add(name);
      try { return await cb({ name }); } finally { held.delete(name); release(); }
    }
  };
}

/** One "browser profile": persistent storage that survives service-worker restarts. */
function newProfile() { return { storage: {}, net: { mode: "ok", calls: [] } }; }

/** Boot (or re-boot) the service worker for a profile. */
function bootWorker(profile, { serverUrl = ORIGIN, enrollmentKey = "" } = {}) {
  const log = { tabUpdates: [], notifications: [], offscreen: 0, alarmMsgs: 0, msgsToTabs: [] };
  const listeners = { nav: [], committed: [], msg: [], alarm: [], startup: [], installed: [] };
  const alarms = new Map();
  let offscreenOpen = false;

  const st = profile.storage;
  const pick = (keys) => {
    if (keys == null) return { ...st };
    if (typeof keys === "string") keys = [keys];
    if (Array.isArray(keys)) return Object.fromEntries(keys.filter(k => k in st).map(k => [k, structuredClone(st[k])]));
    return Object.fromEntries(Object.entries(keys).map(([k, d]) => [k, k in st ? structuredClone(st[k]) : d]));
  };
  const asPromiseOrCb = (fn) => (...a) => {
    const cb = typeof a[a.length - 1] === "function" ? a.pop() : null;
    const out = Promise.resolve().then(() => fn(...a));
    if (cb) { out.then(cb); return undefined; }
    return out;
  };
  const ev = (arr) => ({ addListener: f => arr.push(f) });
  const manifest = JSON.parse(fs.readFileSync(path.join(EXT, "manifest.json"), "utf8"));

  const chrome = {
    runtime: {
      getManifest: () => manifest,
      getURL: p => "chrome-extension://testid/" + p,
      onMessage: ev(listeners.msg), onStartup: ev(listeners.startup), onInstalled: ev(listeners.installed),
      sendMessage: async (m) => { if (m?.target === "pg-offscreen") log.alarmMsgs++; },
      lastError: undefined
    },
    storage: { local: {
      get: asPromiseOrCb(pick),
      set: asPromiseOrCb(async o => { Object.assign(st, structuredClone(o)); }),
      remove: asPromiseOrCb(async k => { [].concat(k).forEach(x => delete st[x]); })
    } },
    alarms: {
      get: (n, cb) => cb(alarms.get(n)), create: (n, o) => alarms.set(n, o), onAlarm: ev(listeners.alarm)
    },
    webNavigation: { onBeforeNavigate: ev(listeners.nav), onCommitted: ev(listeners.committed) },
    tabs: {
      update: async (id, o) => { log.tabUpdates.push({ id, url: o.url }); },
      sendMessage: async (id, m) => { log.msgsToTabs.push({ id, m }); },
      onRemoved: ev([])
    },
    action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    contextMenus: { create: () => {}, onClicked: ev([]) },
    notifications: {
      create: (id, o, cb) => { log.notifications.push(o); cb && cb(id); }, clear: () => {},
      getPermissionLevel: cb => cb("granted")
    },
    offscreen: { createDocument: async () => { if (offscreenOpen) throw new Error("Only a single offscreen document may be created."); offscreenOpen = true; log.offscreen++; } }
  };

  const fetchShim = async (url, opts) => {
    const u = String(url).replace(ORIGIN, BASE);
    profile.net.calls.push({ url: String(url), method: opts?.method || "GET" });
    if (profile.net.mode === "down") throw new TypeError("Failed to fetch");
    const res = await realFetch(u, opts);
    if (profile.net.mode === "lose-response") { await res.arrayBuffer(); throw new TypeError("Failed to fetch (response lost)"); }
    return res;
  };

  const sandbox = {
    console, setTimeout, clearTimeout, AbortController, URL, URLSearchParams, structuredClone,
    crypto: webcrypto, chrome, fetch: fetchShim, Uint8Array, Date, JSON, Math, Promise, Map, Set, Array, Object, String, Number, Error, TypeError, Symbol, RegExp,
    navigator: { userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Safari/537.36", platform: "Win32", locks: makeLocks() }
  };
  sandbox.self = sandbox;
  const ctx = vm.createContext(sandbox);
  sandbox.importScripts = (...files) => files.forEach(f => vm.runInContext(fs.readFileSync(path.join(EXT, f), "utf8"), ctx, { filename: f }));

  // config.js is generated in production; here we emulate what the packager writes.
  const realImport = sandbox.importScripts;
  sandbox.importScripts = (...files) => files.forEach(f => {
    if (f === "config.js") {
      vm.runInContext(`self.PHISHGUARD_DEFAULT_CONFIG = { SERVER_URL: ${JSON.stringify(serverUrl)}, ENROLLMENT_KEY: ${JSON.stringify(enrollmentKey)} };`, ctx);
    } else realImport(f);
  });

  vm.runInContext(fs.readFileSync(path.join(EXT, "background.js"), "utf8"), ctx, { filename: "background.js" });

  const w = {
    log, profile, ctx,
    state: () => vm.runInContext("JSON.parse(JSON.stringify(state))", ctx),
    /** send a runtime message the way popup/content scripts do */
    message: (m, sender = {}) => new Promise((resolve) => {
      let async_ = false;
      for (const l of listeners.msg) { const r = l(m, sender, resolve); if (r === true) async_ = true; }
      if (!async_) setTimeout(() => resolve(undefined), 0);
    }),
    navigate: (url, tabId = 1) => { listeners.nav.forEach(l => l({ url, tabId, frameId: 0 })); },
    alarm: async (name) => { listeners.alarm.forEach(l => l({ name })); await sleep(50); },
    alarms
  };
  return w;
}

const histFor = async (id, q = "") => (await dash("GET", `/events?clientId=${encodeURIComponent(id)}&limit=1000${q}`)).json;
const alertsFor = async (id) => (await dash("GET", `/threats?clientId=${encodeURIComponent(id)}`)).json.alerts;
const tag = randomUUID().slice(0, 6);
const bad = `evil-${tag}.xyz`;

console.log("== A. install → register → dashboard shows the system");
const pA = newProfile();
let A = bootWorker(pA);
let idA;
await step("extension generates identity + secret and registers with the production API", async () => {
  await until(() => A.state().registered, 6000, "registration");
  const s = A.state(); idA = s.clientId;
  assert.match(idA, /^pg-client-/); assert.ok(s.clientSecret.length >= 32);
  assert.equal(s.serverUrl, ORIGIN);
});
await step("dashboard lists Computer A (persisted in Postgres)", async () => {
  const list = (await dash("GET", "/clients")).json.clients;
  const a = list.find(c => c.id === idA); assert.ok(a); assert.equal(a.os, "Windows"); assert.match(a.browser, /Chrome 130/);
});
await step("secret is NOT stored server-side in clear (only a hash) and never returned", async () => {
  const body = JSON.stringify((await dash("GET", "/clients")).json);
  assert.ok(!body.includes(A.state().clientSecret)); assert.ok(!/token_hash|tokenHash/i.test(body));
});
await step("browser restart: same identity, NO duplicate system, NO re-register storm", async () => {
  const secret = A.state().clientSecret;
  const regCallsBefore = pA.net.calls.filter(c => c.url.endsWith("/clients/register")).length;
  A = bootWorker(pA);                         // brand-new service worker, same profile storage
  await sleep(600);
  assert.equal(A.state().clientId, idA); assert.equal(A.state().clientSecret, secret);
  for (let i = 0; i < 4; i++) { A = bootWorker(pA); }  // 4 more cold starts in quick succession
  await sleep(600);
  const list = (await dash("GET", "/clients")).json.clients.filter(c => c.id === idA);
  assert.equal(list.length, 1);
  const regCalls = pA.net.calls.filter(c => c.url.endsWith("/clients/register")).length;
  assert.equal(regCalls, regCallsBefore, "already-registered worker must not re-register on every wake");
});

console.log("== B. dashboard rule → Supabase → extension");
let rule;
await step("admin adds a blacklist rule; it survives a dashboard reload", async () => {
  const r = await dash("POST", "/rules/phishing", { pattern: bad, severity: "CRITICAL", reason: "Credential harvester" });
  assert.equal(r.status, 201); rule = r.json.rule;
  assert.ok((await dash("GET", "/rules")).json.phishing.some(x => x.id === rule.id));
});
await step("heartbeat notices the new rules VERSION and downloads rules only then", async () => {
  const before = pA.net.calls.filter(c => c.url.includes("/extension/rules")).length;
  await A.alarm("pg_heartbeat");
  await until(() => A.state().rules.phishing.some(x => x.pattern === bad), 5000, "rule sync");
  const after = pA.net.calls.filter(c => c.url.includes("/extension/rules")).length;
  assert.equal(after - before, 1);
  await A.alarm("pg_heartbeat"); await sleep(200);   // nothing changed → no second download
  assert.equal(pA.net.calls.filter(c => c.url.includes("/extension/rules")).length, after);
});
await step("rules persist across extension restart, even with the network DOWN", async () => {
  pA.net.mode = "down";
  A = bootWorker(pA); await sleep(400);
  assert.ok(A.state().rules.phishing.some(x => x.pattern === bad), "cached rules must be loaded from chrome.storage");
  pA.net.mode = "ok";
});
await step("popup 'Update Rules' pulls current rules and reports counts", async () => {
  const r = await A.message({ action: "updateRulesNow" });
  assert.equal(r.ok, true); assert.ok(r.phishingCount >= 1);
});

console.log("== C. scan → block → alert + alarm → history");
const evilUrl = `https://login.${bad}/verify?token=1`;
await step("matching URL is blocked INSTANTLY with no network round-trip", async () => {
  const callsBefore = pA.net.calls.length;
  A.navigate(evilUrl);
  await until(() => A.log.tabUpdates.length >= 1, 1000, "redirect");
  const u = new URL(A.log.tabUpdates[0].url);
  assert.ok(u.href.startsWith("chrome-extension://testid/warning.html"));
  assert.equal(u.searchParams.get("url"), evilUrl); assert.equal(u.searchParams.get("rule"), bad);
  assert.equal(u.searchParams.get("ruleType"), "PHISHING"); assert.equal(u.searchParams.get("action"), "BLOCKED");
  assert.equal(pA.net.calls.slice(callsBefore).filter(c => c.url.includes("/scan")).length, 0, "block must not wait on /scan");
});
await step("alarm played once (offscreen audio) + one OS notification naming the rule", async () => {
  await until(() => A.log.alarmMsgs >= 1, 1500, "alarm");
  assert.equal(A.log.alarmMsgs, 1); assert.equal(A.log.offscreen, 1);
  assert.equal(A.log.notifications.length, 1); assert.match(A.log.notifications[0].message, new RegExp(bad));
  assert.match(A.log.notifications[0].message, /BLOCKED/);
});
await step("re-navigating the same URL immediately does not re-alarm or duplicate", async () => {
  A.navigate(evilUrl); await sleep(300);
  assert.equal(A.log.alarmMsgs, 1); assert.equal(A.log.notifications.length, 1);
});
await step("event is delivered by the queue; history has EXACTLY that URL + matched rule", async () => {
  await A.message({ action: "flushQueueNow" });
  const h = await histFor(idA); const e = h.events.filter(x => x.url === evilUrl);
  assert.equal(e.length, 1, "exactly one history row");
  assert.equal(e[0].ruleTriggered, true); assert.equal(e[0].ruleType, "PHISHING");
  assert.equal(e[0].matchedPattern, bad); assert.equal(e[0].matchedRuleId, rule.id); assert.equal(e[0].verdict, "BLOCKED");
  assert.equal((await A.message({ action: "getQueueStatus" })).pending, 0);
});
await step("exactly ONE alert persisted in Supabase for that block, with the rule", async () => {
  const a = (await alertsFor(idA)).filter(x => x.url === evilUrl);
  assert.equal(a.length, 1); assert.equal(a[0].matchedPattern, bad); assert.equal(a[0].status, "ACTIVE");
});
await step("a normal (allowed) URL: goes to server, recorded, NO alarm / redirect", async () => {
  const alarms = A.log.alarmMsgs, tabs = A.log.tabUpdates.length;
  const u = `https://normal-${tag}.example.org/page`;
  A.navigate(u, 2);
  await until(async () => (await histFor(idA, `&search=normal-${tag}`)).events.length === 1, 5000, "history row");
  assert.equal(A.log.alarmMsgs, alarms); assert.equal(A.log.tabUpdates.length, tabs);
});
await step("dashboard/API/Supabase URLs are never scanned or recorded", async () => {
  const before = (await histFor(idA)).total;
  A.navigate(ORIGIN + "/"); A.navigate(ORIGIN + "/api/events"); A.navigate("https://abcd.supabase.co/rest/v1/x");
  await sleep(300); await A.message({ action: "flushQueueNow" });
  assert.equal((await histFor(idA)).total, before);
});
await step("link badge scanning (bulkScan) classifies but does NOT create history", async () => {
  const before = (await histFor(idA)).total;
  const r = await A.message({ action: "bulkScan", urls: [`https://a.${bad}/`, "https://links-only.example.net/x", "not a url"] });
  assert.equal(r.results[0].verdict, "PHISHING"); assert.equal(r.results[2].verdict, "ERROR");
  await sleep(200); await A.message({ action: "flushQueueNow" });
  assert.equal((await histFor(idA)).total, before);
});
await step("popup auto-scan on open is not logged; explicit re-scan is", async () => {
  const u = `https://popup-${tag}.example.org/`;
  await A.message({ action: "scan", url: u, source: "extension-popup", record: false });
  await A.message({ action: "flushQueueNow" });
  assert.equal((await histFor(idA, `&search=popup-${tag}`)).events.length, 0);
  await A.message({ action: "scan", url: u, source: "extension-popup-rescan", record: true });
  // No manual flush: the extension's own 1.5 s debounced flush must deliver it.
  await until(async () => (await histFor(idA, `&search=popup-${tag}`)).events.length === 1, 6000, "debounced flush");
});
await step("in-page blocked click → one alarm, ONE history row + ONE alert (no double-reporting)", async () => {
  const alarms = A.log.alarmMsgs; const u = `https://click-${tag}.xyz/login-verify-account`;
  await A.message({ action: "reportBlockedClick", url: u, score: 0.9 });
  await until(async () => (await histFor(idA, `&search=click-${tag}`)).events.length >= 1, 6000, "click event delivered");
  await sleep(2500);   // give any (buggy) second report time to show up
  assert.equal(A.log.alarmMsgs, alarms + 1);
  assert.equal((await histFor(idA, `&search=click-${tag}`)).events.length, 1);
  assert.equal((await alertsFor(idA)).filter(a => a.url === u).length, 1);
});

console.log("== D. offline, retries, no loss, no duplicates");
await step("server DOWN: navigation still works, event queued (not lost)", async () => {
  pA.net.mode = "down";
  const u = `https://offline-${tag}.example.org/a`;
  A.navigate(u, 3); await sleep(500);
  assert.ok((await A.message({ action: "getQueueStatus" })).pending >= 1);
  A.navigate(evilUrl.replace("verify?token=1", "again?x=" + tag), 4);   // local rule still blocks offline
  await until(() => A.log.tabUpdates.some(t => t.id === 4), 1000, "offline block");
});
await step("server back: queue drains automatically; each URL appears exactly once", async () => {
  pA.net.mode = "ok";
  const r = await A.message({ action: "flushQueueNow" });
  assert.equal(r.ok, true);
  assert.equal((await A.message({ action: "getQueueStatus" })).pending, 0);
  assert.equal((await histFor(idA, `&search=offline-${tag}`)).events.length, 1);
  assert.equal((await histFor(idA, `&search=again%3Fx%3D${tag}`)).events.length, 1);
});
await step("LOST RESPONSE (server stored it, client saw a failure): replay does not duplicate", async () => {
  pA.net.mode = "lose-response";
  const u = `https://lost-${tag}.example.org/`;
  A.navigate(u, 5); await sleep(700);                      // /scan lands server-side, response is "lost"
  pA.net.mode = "ok";
  await A.message({ action: "flushQueueNow" });
  await A.message({ action: "flushQueueNow" });
  assert.equal((await histFor(idA, `&search=lost-${tag}`)).events.length, 1);
});
await step("30 overlapping navigations → all 30 recorded (queue writes are serialized)", async () => {
  for (let i = 0; i < 30; i++) A.navigate(`https://burst${i}-${tag}.example.com/p`, 100 + i);
  await sleep(300);
  for (let i = 0; i < 6; i++) { await A.message({ action: "flushQueueNow" }); await sleep(100); }
  await until(async () => (await histFor(idA, `&search=burst`)).events.filter(e => e.url.includes(tag)).length === 30, 8000, "30 rows");
  const rows = (await histFor(idA, `&search=burst`)).events.filter(e => e.url.includes(tag));
  assert.equal(new Set(rows.map(r => r.url)).size, 30);
});

console.log("== E. rule removal / edit reaches the extension");
await step("admin disables the rule → extension stops blocking after sync", async () => {
  await dash("PATCH", `/rules/phishing/${rule.id}`, { enabled: false });
  await A.message({ action: "updateRulesNow" });
  assert.ok(!A.state().rules.phishing.some(x => x.pattern === bad));
  const tabs = A.log.tabUpdates.length;
  A.navigate(`https://fresh.${bad}/ok`, 9); await sleep(600);
  assert.equal(A.log.tabUpdates.filter((t, i) => i >= tabs && t.id === 9).length, 0, "no local block once disabled");
});
await step("admin re-enables → blocked again; whitelist beats a broader block when more specific", async () => {
  await dash("PATCH", `/rules/phishing/${rule.id}`, { enabled: true });
  const wl = await dash("POST", "/rules/whitelist", { pattern: `docs.${bad}`, description: "internal" });
  await A.message({ action: "updateRulesNow" });
  const t0 = A.log.tabUpdates.length;
  A.navigate(`https://docs.${bad}/guide`, 10); await sleep(300);
  assert.equal(A.log.tabUpdates.length, t0, "docs.<bad> is allowed by the more-specific whitelist");
  A.navigate(`https://other.${bad}/x`, 11); await sleep(300);
  assert.equal(A.log.tabUpdates.length, t0 + 1);
  await A.message({ action: "flushQueueNow" });
  const e = (await histFor(idA, `&search=docs.${bad}`)).events[0];
  assert.equal(e.ruleType, "WHITELIST"); assert.equal(e.verdict, "ALLOWED"); assert.equal(e.matchedPattern, `docs.${bad}`);
});

console.log("== F. second computer, isolation, totals");
const pB = newProfile(); const B = bootWorker(pB); let idB;
await step("Computer B installs → appears as a SEPARATE system", async () => {
  await until(() => B.state().registered, 6000, "B registration"); idB = B.state().clientId;
  assert.notEqual(idB, idA);
  const ids = (await dash("GET", "/clients")).json.clients.map(c => c.id); assert.ok(ids.includes(idA) && ids.includes(idB));
});
await step("B picks up the same rules; scans separate URLs; histories do not mix", async () => {
  await B.message({ action: "updateRulesNow" });
  for (let i = 0; i < 3; i++) B.navigate(`https://b-site${i}-${tag}.example.org/`, 200 + i);
  B.navigate(`https://x.${bad}/`, 210);
  await sleep(400); await B.message({ action: "flushQueueNow" });
  const hb = await histFor(idB), ha = await histFor(idA);
  assert.ok(hb.events.every(e => e.clientId === idB)); assert.ok(ha.events.every(e => e.clientId === idA));
  assert.equal(hb.total, 4);
  assert.equal(hb.events.filter(e => e.verdict === "BLOCKED").length, 1);
});
await step("dashboard totals = sum of real per-system rows", async () => {
  const stats = (await dash("GET", "/stats")).json, sa = (await dash("GET", `/stats?clientId=${idA}`)).json, sb = (await dash("GET", `/stats?clientId=${idB}`)).json;
  const rep = (await dash("GET", "/reports")).json;
  assert.equal(sb.urlsMonitored, 4);
  assert.equal(rep.perSystem.find(s => s.clientId === idA).totalScanned, sa.urlsMonitored);
  assert.equal(rep.perSystem.find(s => s.clientId === idB).totalScanned, sb.urlsMonitored);
  assert.equal(stats.urlsMonitored, rep.perSystem.reduce((n, s) => n + s.totalScanned, 0));
});

console.log("== G. recovery + safety");
await step("admin removes Computer A → extension transparently re-enrols (no crash, no data mixing)", async () => {
  assert.equal((await dash("DELETE", `/clients/${idA}`)).status, 200);
  assert.ok(!(await dash("GET", "/clients")).json.clients.some(c => c.id === idA));
  await A.alarm("pg_heartbeat");
  await until(async () => (await dash("GET", "/clients")).json.clients.some(c => c.id === idA), 6000, "re-enrol");
  A.navigate(`https://after-delete-${tag}.example.org/`, 300); await sleep(500); await A.message({ action: "flushQueueNow" });
  assert.equal((await histFor(idA, `&search=after-delete-${tag}`)).events.length, 1);
  assert.equal((await histFor(idB)).total, 4, "B untouched");
});
await step("legacy install (has clientId, no secret) keeps its id and gets a secret", async () => {
  const pL = newProfile(); pL.storage.phishguardClientId = "pg-client-legacy" + tag; pL.storage.phishguardClientName = "Legacy-PC";
  const L = bootWorker(pL);
  await until(() => L.state().registered, 6000, "legacy registration");
  assert.equal(L.state().clientId, "pg-client-legacy" + tag); assert.ok(L.state().clientSecret.length >= 32);
  assert.equal((await dash("GET", "/clients")).json.clients.filter(c => c.id === "pg-client-legacy" + tag).length, 1);
});
await step("NOT configured (no server URL): extension makes zero network calls and does not crash", async () => {
  const p0 = newProfile(); const N = bootWorker(p0, { serverUrl: "" }); await sleep(400);
  N.navigate("https://anything.example.org/"); await sleep(300);
  const s = await N.message({ action: "getStatus" });
  assert.equal(s.configured, false); assert.equal(p0.net.calls.length, 0);
});
await step("refuses http:// and localhost server URLs", async () => {
  for (const bad of ["http://phishguard.example.app", "https://localhost:3000", "https://127.0.0.1", "https://192.168.1.5"]) {
    const p1 = newProfile(); const X = bootWorker(p1, { serverUrl: bad }); await sleep(150);
    assert.equal((await X.message({ action: "getStatus" })).configured, false, bad); assert.equal(p1.net.calls.length, 0, bad);
  }
});
await step("a user override to a non-https URL is ignored (falls back to packaged default)", async () => {
  const p2 = newProfile(); p2.storage.phishguardServerUrl = "http://localhost:3000";
  const X = bootWorker(p2); await sleep(400);
  assert.equal(X.state().serverUrl, ORIGIN);
});
await step("a failed rules download never wipes the cached rules", async () => {
  const before = JSON.stringify(A.state().rules);
  pA.net.mode = "down"; const r = await A.message({ action: "updateRulesNow" }); pA.net.mode = "ok";
  assert.equal(r.ok, false); assert.equal(JSON.stringify(A.state().rules), before);
  assert.equal(JSON.stringify(pA.storage.pgRules), before);
});

console.log(`\n${pass} extension checks passed${process.exitCode ? " — WITH FAILURES" : ""}`);
process.exit(process.exitCode || 0);
