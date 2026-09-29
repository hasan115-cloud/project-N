const assert = require("assert");
const C = require("../shared/pgcore.cjs");
let n = 0; const t = (name, fn) => { fn(); n++; console.log("ok -", name); };

t("normalizeUrl basics", () => {
  const r = C.normalizeUrl("HTTPS://WWW.Example.COM:443/Login/?a=1#frag");
  assert(r.ok); assert.strictEqual(r.host, "example.com"); assert.strictEqual(r.normalized, "example.com/login?a=1");
});
t("root has no trailing slash", () => assert.strictEqual(C.normalizeUrl("https://example.com/").normalized, "example.com"));
t("rejects non-http / malformed / oversize", () => {
  assert(!C.normalizeUrl("javascript:alert(1)").ok); assert(!C.normalizeUrl("chrome://x").ok);
  assert(!C.normalizeUrl("not a url").ok); assert(!C.normalizeUrl("https://a.com/" + "x".repeat(3000)).ok); assert(!C.normalizeUrl(null).ok);
});
t("credentials stripped from href", () => assert(!C.normalizeUrl("https://user:pw@example.com/").href.includes("pw")));
t("pattern normalization", () => {
  assert.deepStrictEqual(C.normalizePattern("https://www.Evil-Login.xyz/"), { ok: true, pattern: "evil-login.xyz", kind: "domain" });
  assert.strictEqual(C.normalizePattern("*.example.com").pattern, "example.com");
  assert.strictEqual(C.normalizePattern("https://example.com/Login/").kind, "url");
});
t("pattern rejects junk / too broad", () => {
  for (const bad of ["", "   ", "com", "co.uk", "a b.com", "ex*mple.com", "localhost", "http://", "user:pw@x.com"]) assert(!C.normalizePattern(bad).ok, "should reject: " + bad);
});
const wl = (p, extra={}) => ({ id: "wl_"+p, pattern: p, createdAt: "2026-01-01", ...extra });
const ph = (p, extra={}) => ({ id: "ph_"+p, pattern: p, createdAt: "2026-01-01", ...extra });
t("SECURITY: whitelist 'paypal.com' must NOT whitelist evil.xyz/paypal.com (old substring bug)", () => {
  const r = C.evaluateRules("https://evil.xyz/paypal.com", { whitelist: [wl("paypal.com")], phishing: [] });
  assert.strictEqual(r, null);
  assert.strictEqual(C.evaluateRules("https://notpaypal.com/", { whitelist: [wl("paypal.com")], phishing: [] }), null);
  assert.strictEqual(C.evaluateRules("https://paypal.com.evil.xyz/", { whitelist: [wl("paypal.com")], phishing: [] }), null);
});
t("domain rule matches apex, www, and subdomains", () => {
  const rules = { whitelist: [], phishing: [ph("evil.xyz")] };
  for (const u of ["https://evil.xyz", "http://www.evil.xyz/a", "https://a.b.evil.xyz/?q=1"]) assert.strictEqual(C.evaluateRules(u, rules).action, "BLOCKED", u);
});
t("URL-path rule boundary", () => {
  const rules = { whitelist: [], phishing: [ph("example.com/login")] };
  assert(C.evaluateRules("https://example.com/login", rules));
  assert(C.evaluateRules("https://example.com/login/verify?x=1", rules));
  assert(C.evaluateRules("https://example.com/login?x=1", rules));
  assert.strictEqual(C.evaluateRules("https://example.com/loginx", rules), null);
  assert.strictEqual(C.evaluateRules("https://example.com/", rules), null);
});
t("disabled rules ignored", () => assert.strictEqual(C.evaluateRules("https://evil.xyz", { whitelist: [], phishing: [ph("evil.xyz", { enabled: false })] }), null));
t("PRECEDENCE: more specific block beats broader whitelist", () => {
  const r = C.evaluateRules("https://login.example.com/", { whitelist: [wl("example.com")], phishing: [ph("login.example.com")] });
  assert.strictEqual(r.type, "PHISHING");
});
t("PRECEDENCE: more specific allow beats broader block", () => {
  const r = C.evaluateRules("https://docs.example.com/", { whitelist: [wl("docs.example.com")], phishing: [ph("example.com")] });
  assert.strictEqual(r.type, "WHITELIST");
});
t("PRECEDENCE: equal specificity -> whitelist wins", () => {
  const r = C.evaluateRules("https://example.com/", { whitelist: [wl("example.com")], phishing: [ph("example.com")] });
  assert.strictEqual(r.type, "WHITELIST"); assert.strictEqual(r.action, "ALLOWED");
});
t("PRECEDENCE: deterministic regardless of array order", () => {
  const a = [ph("x.example.com", {id:"a"}), ph("y.example.com", {id:"b"})];
  const w = [wl("example.com")];
  const r1 = C.evaluateRules("https://x.example.com", { whitelist: w, phishing: a });
  const r2 = C.evaluateRules("https://x.example.com", { whitelist: w, phishing: [...a].reverse() });
  assert.strictEqual(r1.ruleId, r2.ruleId);
});
t("safe apex + internal hosts", () => {
  assert(C.isSafeApex("mail.google.com")); assert(C.isSafeApex("bbc.co.uk") === false);
  assert(C.isInternalHost("abc.supabase.co")); assert(C.isInternalHost("phishguard.netlify.app", ["phishguard.netlify.app"])); assert(!C.isInternalHost("example.com", ["phishguard.netlify.app"]));
});
console.log(`\n${n} tests passed`);
