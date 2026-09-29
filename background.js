// PhishGuard Background Service Worker (Manifest V3) — v1.5
//
// Data flow (nothing here is persisted anywhere except chrome.storage.local
// for identity/rules-cache/offline-queue; the SERVER + Supabase are the source
// of truth for rules, history and alerts):
//
//   navigation ──► local decision (shared matcher, instant, no network)
//                     ├─ admin BLOCK rule  → redirect + alarm NOW, event queued
//                     ├─ admin ALLOW rule / safe list / trusted → allow, event queued
//                     └─ otherwise → POST /api/scan (async; never blocks the browser)
//   event queue ──► POST /api/url-events (batched, idempotent, retried, survives restarts)
//   rules       ──► GET  /api/extension/rules?since=<version> (only when the version changed)
//
// Alerts are created SERVER-SIDE, atomically with the history row, so there is
// exactly one alert per detection no matter how many retries happen.

importScripts("config.js", "pg-core.js");
const Core = self.PGCore;

const EXT_VERSION = chrome.runtime.getManifest().version;
const CACHE_TTL_MS = 15 * 60 * 1000;
const SCAN_TIMEOUT_MS = 8 * 1000;
const API_TIMEOUT_MS = 10 * 1000;
const BULK_TIMEOUT_MS = 20 * 1000;
const FLUSH_DEBOUNCE_MS = 1500;
const RULES_MAX_AGE_MS = 5 * 60 * 1000;
const QUEUE_KEY = "pgUrlEventQueue";
const QUEUE_MAX = 5000;
const QUEUE_MAX_AGE_MS = 7 * 24 * 3600 * 1000; // server rejects older timestamps anyway
const FLUSH_BATCH = 200;
const RULES_KEY = "pgRules";

// ─── In-memory (rebuildable) state ──────────────────────────────────────────
const verdictCache = new Map();   // normalized url → { time, data }
const inFlight = new Map();       // normalized url → Promise<data>
const bypassedUrls = new Map();   // url → expiry ms
const tabStats = new Map();       // tabId → { total, phishing, suspicious, safe }
const recentNav = new Map();      // tabId|url → time   (collapses duplicate nav events)
const recentAlerts = new Map();   // url → time         (one alarm/notification per block)

const state = {
    serverUrl: "",
    clientId: "",
    clientSecret: "",
    clientName: "",
    registered: false,
    trusted: [],
    rules: { version: 0, whitelist: [], phishing: [] },
    rulesSyncedAt: 0,
    lastError: ""
};

// ─── Small helpers ──────────────────────────────────────────────────────────
function randomHex(bytes) {
    const a = new Uint8Array(bytes);
    crypto.getRandomValues(a);
    return Array.from(a, b => b.toString(16).padStart(2, "0")).join("");
}
const newEventId = () => (crypto.randomUUID ? crypto.randomUUID() : `evt-${Date.now()}-${randomHex(6)}`);

async function fetchWithTimeout(url, options, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        return await fetch(url, { ...options, signal: controller.signal });
    } finally {
        clearTimeout(timer);
    }
}

class ApiError extends Error {
    constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}

// Only https:// and never a local/private address. Returns the origin or "".
function validateServerUrl(raw) {
    try {
        const u = new URL(String(raw || "").trim());
        if (u.protocol !== "https:") return "";
        if (/^(localhost|127\.|10\.|192\.168\.|0\.0\.0\.0|\[::1\])/.test(u.hostname) || /\.local$/.test(u.hostname)) return "";
        return u.origin;
    } catch { return ""; }
}

function resolveServerUrl(override) {
    const def = (typeof PHISHGUARD_DEFAULT_CONFIG !== "undefined" && PHISHGUARD_DEFAULT_CONFIG.SERVER_URL) || "";
    return validateServerUrl(override) || validateServerUrl(def);
}

function isInternal(host) {
    let own = "";
    try { own = new URL(state.serverUrl).hostname; } catch { /* not configured */ }
    return Core.isInternalHost(host, own ? [own] : []);
}

// ─── Identity / config (loaded once per service-worker wake) ────────────────
//
// `ready` is a single shared promise: every handler awaits it, so concurrent
// events on a cold start can never each generate their own identity (which
// would enrol duplicate systems for one install).
async function loadState() {
    const s = await chrome.storage.local.get([
        "phishguardServerUrl", "phishguardClientId", "phishguardClientSecret", "phishguardClientName",
        "pgRegistered", "trustedDomains", RULES_KEY, "pgRulesSyncedAt"
    ]);
    // A saved override is used only if it passes validation; the packaged default is otherwise used.
    state.serverUrl = resolveServerUrl(s.phishguardServerUrl);

    const toSet = {};
    if (s.phishguardClientId) state.clientId = s.phishguardClientId;
    else { state.clientId = "pg-client-" + randomHex(10); toSet.phishguardClientId = state.clientId; }

    // Installs from before v1.5 have an id but no secret: keep the id (stable
    // identity, history stays attached) and add a secret; the server lets the
    // first registration claim an id that has no credentials yet.
    if (s.phishguardClientSecret && s.phishguardClientSecret.length >= 32) state.clientSecret = s.phishguardClientSecret;
    else { state.clientSecret = randomHex(32); toSet.phishguardClientSecret = state.clientSecret; toSet.pgRegistered = false; s.pgRegistered = false; }

    if (s.phishguardClientName) state.clientName = s.phishguardClientName;
    else {
        const platform = (navigator.userAgentData?.platform || navigator.platform || "Workstation").replace(/[^a-zA-Z0-9]/g, "") || "Workstation";
        state.clientName = `${platform}-${state.clientId.slice(-4).toUpperCase()}`;
        toSet.phishguardClientName = state.clientName;
    }
    if (Object.keys(toSet).length) await chrome.storage.local.set(toSet);

    state.registered = s.pgRegistered === true;
    state.trusted = Array.isArray(s.trustedDomains) ? s.trustedDomains : [];
    const r = s[RULES_KEY];
    if (r && Array.isArray(r.whitelist) && Array.isArray(r.phishing)) state.rules = r;
    state.rulesSyncedAt = s.pgRulesSyncedAt || 0;
}
const ready = loadState().catch(e => { console.error("PhishGuard: state init failed", e); state.lastError = String(e?.message || e); });

function getSystemInfo() {
    const ua = navigator.userAgent;
    let browser = "Chrome";
    const m = ua.match(/Chrome\/([0-9.]+)/);
    if (m) browser = `Chrome ${m[1].split(".")[0]}`;
    let os = "Linux";
    if (ua.includes("Windows")) os = "Windows";
    else if (ua.includes("Macintosh") || ua.includes("Mac OS")) os = "macOS";
    else if (ua.includes("Android")) os = "Android";
    else if (ua.includes("CrOS")) os = "ChromeOS";
    return {
        clientId: state.clientId,
        clientName: state.clientName,
        os, browser,
        platform: navigator.platform || os,
        extensionVersion: EXT_VERSION
    };
}

// ─── API layer: auth headers, timeout, 401 → re-register once ───────────────
async function api(path, { method = "GET", body, timeout = API_TIMEOUT_MS } = {}) {
    await ready;
    if (!state.serverUrl) throw new ApiError(0, "No valid HTTPS server URL is configured", "not_configured");
    const attempt = async () => {
        const headers = { "X-Client-ID": state.clientId, "Authorization": "Bearer " + state.clientSecret };
        if (body !== undefined) headers["Content-Type"] = "application/json";
        return fetchWithTimeout(`${state.serverUrl}/api${path}`, {
            method, headers, cache: "no-store",
            body: body === undefined ? undefined : JSON.stringify(body)
        }, timeout);
    };
    let res = await attempt();
    if (res.status === 401) {
        // Unknown system (removed on the dashboard) or lost credentials: enrol again, once.
        state.registered = false;
        await register();
        res = await attempt();
    }
    let json = null;
    try { json = await res.json(); } catch { /* non-JSON */ }
    if (!res.ok) throw new ApiError(res.status, json?.error || `HTTP ${res.status}`, json?.code);
    state.lastError = "";
    return json;
}

// ─── Registration (idempotent, single-flight) ───────────────────────────────
let registering = null;
function register() {
    if (registering) return registering;
    registering = (async () => {
        await ready;
        if (!state.serverUrl) throw new ApiError(0, "No valid HTTPS server URL is configured", "not_configured");
        const headers = { "Content-Type": "application/json", "Authorization": "Bearer " + state.clientSecret };
        const key = typeof PHISHGUARD_DEFAULT_CONFIG !== "undefined" && PHISHGUARD_DEFAULT_CONFIG.ENROLLMENT_KEY;
        if (key) headers["X-Enrollment-Key"] = key;
        try {
            const res = await fetchWithTimeout(`${state.serverUrl}/api/clients/register`, {
                method: "POST", headers, cache: "no-store", body: JSON.stringify(getSystemInfo())
            }, API_TIMEOUT_MS);
            let json = null;
            try { json = await res.json(); } catch { /* ignore */ }
            if (!res.ok) throw new ApiError(res.status, json?.error || `HTTP ${res.status}`, json?.code);
            state.registered = true;
            state.lastError = "";
            await chrome.storage.local.set({ pgRegistered: true });
            if (json?.rulesVersion !== undefined && json.rulesVersion !== state.rules.version) syncRules().catch(() => {});
            return json;
        } catch (e) {
            state.lastError = `Registration failed: ${e.message}`;
            throw e;
        } finally {
            registering = null;
        }
    })();
    return registering;
}

async function ensureRegistered() {
    await ready;
    if (!state.registered) await register();
}

// ─── Heartbeat ──────────────────────────────────────────────────────────────
async function sendHeartbeat() {
    try {
        await ready;
        if (!state.serverUrl) return;
        await ensureRegistered();
        let total = 0, phishing = 0, suspicious = 0, safe = 0;
        tabStats.forEach(s => { total += s.total || 0; phishing += s.phishing || 0; suspicious += s.suspicious || 0; safe += s.safe || 0; });
        const data = await api("/clients/heartbeat", {
            method: "POST",
            body: { stats: { total, phishing, suspicious, safe }, extensionVersion: EXT_VERSION },
            timeout: 5000
        });
        // The response carries only a VERSION. Rules are downloaded only if it changed.
        if (data.rulesVersion !== undefined && data.rulesVersion !== state.rules.version) await syncRules();
        flushQueue();
    } catch (e) {
        state.lastError = e.message;   // offline / server down: silent, retried next alarm
    }
}

// ─── Rules: server → chrome.storage → memory ────────────────────────────────
async function syncRules({ force = false } = {}) {
    await ready;
    await ensureRegistered();
    const q = force ? "" : `?since=${encodeURIComponent(state.rules.version)}`;
    const data = await api(`/extension/rules${q}`, { timeout: 8000 });
    state.rulesSyncedAt = Date.now();
    if (data.changed === false) {
        await chrome.storage.local.set({ pgRulesSyncedAt: state.rulesSyncedAt });
        return { changed: false };
    }
    // Replace only after a complete, well-formed response. A failed request throws
    // before reaching here, so the last-known-good rules are never erased.
    if (!Array.isArray(data.whitelist) || !Array.isArray(data.phishing)) throw new Error("Malformed rules response");
    state.rules = { version: data.version, whitelist: data.whitelist, phishing: data.phishing };
    verdictCache.clear(); // verdicts computed under old rules are stale
    await chrome.storage.local.set({ [RULES_KEY]: state.rules, pgRulesSyncedAt: state.rulesSyncedAt });
    return { changed: true };
}

// Popup "Update Rules" button.
async function fetchRulesNow() {
    try {
        await syncRules({ force: true });
        return { ok: true, whitelistCount: state.rules.whitelist.length, phishingCount: state.rules.phishing.length, version: state.rules.version };
    } catch (err) {
        return { ok: false, error: err?.message || "Rule sync failed (server unreachable)" };
    }
}

// ─── Durable, idempotent URL-event queue ────────────────────────────────────
// Storage read-modify-write is guarded by a Web Lock: without it, two navigations
// enqueuing at the same moment both read the same array and one event is lost.
let flushTimer = null;
let flushFailures = 0;
let nextFlushAt = 0;

async function enqueue(url, source, eventId) {
    if (!/^https?:\/\//i.test(url || "")) return;
    try {
        await navigator.locks.request("pg-queue", async () => {
            const { [QUEUE_KEY]: queue = [] } = await chrome.storage.local.get(QUEUE_KEY);
            queue.push({ eventId: eventId || newEventId(), url: url.slice(0, 2048), source: source || "extension-navigation", observedAt: new Date().toISOString() });
            const cutoff = Date.now() - QUEUE_MAX_AGE_MS;
            const fresh = queue.filter(e => Date.parse(e.observedAt) >= cutoff);
            await chrome.storage.local.set({ [QUEUE_KEY]: fresh.length > QUEUE_MAX ? fresh.slice(fresh.length - QUEUE_MAX) : fresh });
        });
    } catch (e) {
        console.warn("PhishGuard: could not queue URL event:", e?.message);
        return;
    }
    scheduleFlush();
}

function scheduleFlush() {
    clearTimeout(flushTimer);
    flushTimer = setTimeout(() => flushQueue(), FLUSH_DEBOUNCE_MS);
}

async function flushQueue({ force = false } = {}) {
    return navigator.locks.request("pg-flush", { ifAvailable: true }, async lock => {
        if (!lock) return { ok: false, reason: "flush already running" };
        if (!force && Date.now() < nextFlushAt) return { ok: false, reason: "backing off after a failure" };
        await ready;
        if (!state.serverUrl) return { ok: false, reason: "not configured" };
        let flushed = 0;
        try {
            for (let round = 0; round < 50; round++) {
                const { [QUEUE_KEY]: queue = [] } = await chrome.storage.local.get(QUEUE_KEY);
                if (queue.length === 0) break;
                await ensureRegistered();
                const batch = queue.slice(0, FLUSH_BATCH);
                const data = await api("/url-events", { method: "POST", body: { clientName: state.clientName, events: batch }, timeout: 15000 });
                const acked = new Set(data.acknowledgedIds || []);
                // Remove ONLY ids the server confirmed. Re-read inside the lock so events
                // enqueued during the round trip are not lost.
                await navigator.locks.request("pg-queue", async () => {
                    const { [QUEUE_KEY]: current = [] } = await chrome.storage.local.get(QUEUE_KEY);
                    await chrome.storage.local.set({ [QUEUE_KEY]: current.filter(e => !acked.has(e.eventId)) });
                });
                if (acked.size === 0) throw new Error("server acknowledged nothing");
                flushed += acked.size;
                if (data.rulesVersion !== undefined && data.rulesVersion !== state.rules.version) syncRules().catch(() => {});
            }
            flushFailures = 0; nextFlushAt = 0;
            return { ok: true, flushed };
        } catch (err) {
            flushFailures++;
            nextFlushAt = Date.now() + Math.min(5 * 60 * 1000, 2000 * 2 ** Math.min(flushFailures, 8));
            state.lastError = err?.message || "flush failed";
            return { ok: false, error: state.lastError, flushed };   // everything unconfirmed stays queued
        }
    });
}

// ─── Decisions ──────────────────────────────────────────────────────────────
function ruleDecision(m) {
    const block = m.type === "PHISHING";
    return {
        verdict: block ? "PHISHING" : "SAFE",
        action: block ? "BLOCKED" : "ALLOWED",
        score: block ? 0.99 : 0,
        risk_score: block ? 0.99 : 0,
        reasons: [block
            ? `Blocked by Administrator Phishing Rule: "${m.pattern}"${m.rule?.reason ? " — " + m.rule.reason : ""}`
            : `Allowed by Administrator Whitelist Rule: "${m.pattern}"`],
        whitelisted: !block,
        policyMatched: block,
        ruleTriggered: true,
        ruleType: m.type,
        matchedRule: { id: m.ruleId, pattern: m.pattern, type: m.type },
        decisionSource: "rule"
    };
}

function isTrusted(host) {
    return state.trusted.some(d => host === d || host.endsWith("." + d));
}

async function addToRecentScans(url, verdict, score) {
    try {
        const { recentScans = [] } = await chrome.storage.local.get("recentScans");
        const updated = [{ url, verdict, score: score ?? 0, time: Date.now() }, ...recentScans.filter(r => r.url !== url)].slice(0, 10);
        await chrome.storage.local.set({ recentScans: updated });
    } catch { /* non-critical */ }
}

// scanUrl: ONE observation == ONE eventId, minted before any branch, so the
// observation is recorded exactly once however its verdict was reached.
async function scanUrl(rawUrl, source = "extension-navigation", { record = true } = {}) {
    await ready;
    const norm = Core.normalizeUrl(rawUrl);
    if (!norm.ok) return { verdict: "ERROR", error: norm.error };
    // Never scan or record the PhishGuard dashboard/API or Supabase itself.
    if (isInternal(norm.host)) {
        return { verdict: "SAFE", action: "ALLOWED", score: 0, reasons: ["PhishGuard dashboard address"], internal: true };
    }
    const eventId = newEventId();
    const key = norm.normalized;

    // 1. Administrator rules (deterministic precedence, shared with the server)
    const m = Core.evaluateRules(norm, state.rules);
    if (m) {
        const d = ruleDecision(m);
        verdictCache.set(key, { time: Date.now(), data: d });
        addToRecentScans(rawUrl, d.verdict, d.score);
        if (record) enqueue(rawUrl, source, eventId);
        return { ...d, eventId };
    }
    // 2. Known-safe apex / user-trusted domain
    if (Core.isSafeApex(norm.host)) {
        if (record) enqueue(rawUrl, source, eventId);
        return { verdict: "SAFE", action: "ALLOWED", score: 0, whitelisted: true, reasons: ["Domain is in standard safe directory"], decisionSource: "safe-list" };
    }
    if (isTrusted(norm.host)) {
        if (record) enqueue(rawUrl, source, eventId);
        return { verdict: "SAFE", action: "ALLOWED", score: 0, trusted: true, reasons: ["Domain is in user trusted list"], decisionSource: "trusted" };
    }
    // 3. Fresh cached server verdict (a revisit is still its own history event)
    const cached = verdictCache.get(key);
    if (cached && Date.now() - cached.time < CACHE_TTL_MS) {
        if (record) enqueue(rawUrl, source, eventId);
        return cached.data;
    }
    if (inFlight.has(key)) {
        if (record) enqueue(rawUrl, source, eventId);
        return inFlight.get(key);
    }
    // 4. Ask the server (asynchronous — callers never hold up navigation on this)
    const promise = (async () => {
        try {
            const data = await api("/scan", {
                method: "POST",
                body: { url: rawUrl, source, eventId, record, observedAt: new Date().toISOString() },
                timeout: SCAN_TIMEOUT_MS
            });
            verdictCache.set(key, { time: Date.now(), data });
            if (data.verdict && data.verdict !== "ERROR") addToRecentScans(rawUrl, data.verdict, data.score ?? 0);
            return { ...data, eventId };
        } catch (err) {
            console.warn("PhishGuard scan relay error:", err.message);
            // Not confirmed by the server → queue the SAME eventId; a lost response is deduped on replay.
            if (record) enqueue(rawUrl, source, eventId);
            return { verdict: "SAFE", action: "ALLOWED", score: 0.1, offline: true, reasons: ["Detection server unreachable; local rules only"] };
        } finally {
            inFlight.delete(key);
        }
    })();
    inFlight.set(key, promise);
    return promise;
}

// Link badges on pages. Classification only — NOT written to URL History,
// because the user has not visited these links.
async function bulkScanUrls(urls) {
    await ready;
    const results = new Array(urls.length);
    const toFetch = [];   // { idx, url }
    urls.forEach((u, idx) => {
        const norm = Core.normalizeUrl(u);
        if (!norm.ok) { results[idx] = { verdict: "ERROR", error: norm.error }; return; }
        if (isInternal(norm.host)) { results[idx] = { verdict: "SAFE", score: 0 }; return; }
        const m = Core.evaluateRules(norm, state.rules);
        if (m) { results[idx] = ruleDecision(m); return; }
        if (Core.isSafeApex(norm.host) || isTrusted(norm.host)) { results[idx] = { verdict: "SAFE", score: 0 }; return; }
        const c = verdictCache.get(norm.normalized);
        if (c && Date.now() - c.time < CACHE_TTL_MS) { results[idx] = c.data; return; }
        toFetch.push({ idx, url: u, key: norm.normalized });
    });
    for (let i = 0; i < toFetch.length; i += 50) {
        const chunk = toFetch.slice(i, i + 50);
        try {
            const data = await api("/bulk-scan", { method: "POST", body: { urls: chunk.map(c => c.url) }, timeout: BULK_TIMEOUT_MS });
            (data.results || []).forEach((r, j) => {
                results[chunk[j].idx] = r;
                if (r && r.verdict && r.verdict !== "ERROR") verdictCache.set(chunk[j].key, { time: Date.now(), data: r });
            });
        } catch {
            chunk.forEach(c => { results[c.idx] = { verdict: "SAFE", score: 0.1, offline: true }; });
        }
    }
    return results.map(r => r || { verdict: "SAFE", score: 0.1 });
}

// ─── Alerts: alarm + notification + warning page (server records the alert) ─
async function soundEnabled() {
    try { const { pgSoundEnabled } = await chrome.storage.local.get("pgSoundEnabled"); return pgSoundEnabled !== false; }
    catch { return true; }
}

async function playAlarm() {
    if (!(await soundEnabled())) return;
    try {
        if (chrome.offscreen) {
            try {
                await chrome.offscreen.createDocument({
                    url: "offscreen.html",
                    reasons: ["AUDIO_PLAYBACK"],
                    justification: "Play an audible alarm when a phishing URL is blocked"
                });
            } catch (e) {
                if (!/single offscreen document|already exists/i.test(String(e?.message))) throw e;
            }
            chrome.runtime.sendMessage({ target: "pg-offscreen", type: "play-alarm" }).catch(() => {});
        }
    } catch (e) {
        console.warn("PhishGuard: could not play alarm:", e?.message);
    }
}

function showOsNotification(url, score, matched) {
    if (!chrome.notifications) return;
    let domain = url;
    try { domain = new URL(url).hostname; } catch { /* keep raw */ }
    const id = `pg-threat-${Date.now()}`;
    try {
        chrome.notifications.create(id, {
            type: "basic",
            iconUrl: chrome.runtime.getURL("icon.png"),
            title: "⚠ PhishGuard: Threat Blocked",
            message: `${domain}${matched ? `\nMatched rule: ${matched}` : ""}\nAction: BLOCKED (risk ${(score * 100).toFixed(0)}%)`,
            priority: 2
        }, () => {
            if (chrome.runtime.lastError) console.error("PhishGuard: notification failed:", chrome.runtime.lastError.message);
            else setTimeout(() => { try { chrome.notifications.clear(id); } catch { /* gone */ } }, 20000);
        });
    } catch (e) { console.error("PhishGuard: notification threw:", e); }
}

// ONE place decides "this is a real block" → alarm + notification, at most once per URL per 10s.
function raiseBlockAlert(url, score, matched) {
    const now = Date.now();
    for (const [k, t] of recentAlerts) if (now - t > 10000) recentAlerts.delete(k);
    if (recentAlerts.has(url)) return;
    recentAlerts.set(url, now);
    playAlarm();
    showOsNotification(url, score, matched);
}

function redirectToWarning(tabId, url, data, verdict) {
    const isBlock = verdict === "PHISHING";
    if (isBlock) raiseBlockAlert(url, data.score ?? data.risk_score ?? 0.9, data.matchedRule?.pattern);
    const q = new URLSearchParams({
        url,
        score: String(data.score ?? data.risk_score ?? 0),
        reasons: JSON.stringify(data.reasons || []),
        verdict,
        rule: data.matchedRule?.pattern || "",
        ruleType: data.ruleType || "",
        action: isBlock ? "BLOCKED" : "WARNING"
    });
    chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning.html") + "?" + q.toString() }).catch(() => {});
}

function act(tabId, url, data) {
    if (!data || data.verdict === "ERROR" || data.internal) return;
    if (data.verdict === "PHISHING") redirectToWarning(tabId, url, data, "PHISHING");
    else if (data.verdict === "SUSPICIOUS") redirectToWarning(tabId, url, data, "SUSPICIOUS");
    chrome.storage.local.set({ [`tabScan_${tabId}`]: { url, data, time: Date.now() } }).catch(() => {});
}

// ─── Navigation interception ────────────────────────────────────────────────
function handleNavigation(details, source) {
    const url = details.url;
    if (!/^https?:\/\//i.test(url)) return;
    const b = bypassedUrls.get(url);
    if (b) { bypassedUrls.delete(url); if (b > Date.now()) return; }

    // Collapse the duplicate events Chrome can emit for one navigation (start + committed redirect).
    const k = details.tabId + "|" + url;
    const now = Date.now();
    if (now - (recentNav.get(k) || 0) < 3000) return;
    recentNav.set(k, now);
    if (recentNav.size > 200) for (const [key, t] of recentNav) if (now - t > 3000) recentNav.delete(key);

    scanUrl(url, source).then(data => act(details.tabId, url, data)).catch(() => {});
}

chrome.webNavigation.onBeforeNavigate.addListener(details => {
    if (details.frameId !== 0) return;
    handleNavigation(details, "extension-navigation");
});

// A server-side redirect (short links, tracking hops) commits at a URL that was never
// seen by onBeforeNavigate — scan where the user actually landed.
chrome.webNavigation.onCommitted.addListener(details => {
    if (details.frameId !== 0) return;
    if ((details.transitionQualifiers || []).includes("server_redirect")) handleNavigation(details, "extension-redirect");
});

// ─── Badge ──────────────────────────────────────────────────────────────────
function updateBadge(tabId, stats) {
    if (!stats || (stats.phishing === 0 && stats.suspicious === 0)) {
        chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
        return;
    }
    if (stats.phishing > 0) {
        chrome.action.setBadgeText({ text: String(stats.phishing), tabId }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ color: "#dc3545", tabId }).catch(() => {});
    } else {
        chrome.action.setBadgeText({ text: String(stats.suspicious), tabId }).catch(() => {});
        chrome.action.setBadgeBackgroundColor({ color: "#ffc107", tabId }).catch(() => {});
    }
}

// ─── Messages (popup / content scripts) ─────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.target === "pg-offscreen") return; // addressed to the offscreen document

    switch (message.action) {
        case "scan":
            scanUrl(message.url, message.source || "extension-popup", { record: message.record !== false })
                .then(sendResponse).catch(() => sendResponse({ verdict: "ERROR" }));
            return true;

        case "bulkScan":
            bulkScanUrls(message.urls || []).then(results => sendResponse({ results })).catch(() => sendResponse({ results: [] }));
            return true;

        case "reportBlockedClick": {
            // A phishing link the user tried to open was stopped in-page: this is a real block.
            // Recorded through the same durable queue → the server writes history + ONE alert.
            enqueue(message.url, "in-page-click", newEventId());
            raiseBlockAlert(message.url, message.score || 0.8, message.rule || "");
            sendResponse({ ok: true });
            return false;
        }

        case "updateRulesNow":
            fetchRulesNow().then(sendResponse);
            return true;

        case "getStatus":
            ready.then(async () => {
                const { [QUEUE_KEY]: q = [] } = await chrome.storage.local.get(QUEUE_KEY);
                sendResponse({
                    configured: Boolean(state.serverUrl), serverUrl: state.serverUrl,
                    registered: state.registered, clientId: state.clientId, clientName: state.clientName,
                    pending: q.length, rulesVersion: state.rules.version,
                    whitelistCount: state.rules.whitelist.length, phishingCount: state.rules.phishing.length,
                    rulesSyncedAt: state.rulesSyncedAt, lastError: state.lastError
                });
            });
            return true;

        case "getQueueStatus":
            chrome.storage.local.get(QUEUE_KEY).then(r => sendResponse({ pending: (r[QUEUE_KEY] || []).length })).catch(() => sendResponse({ pending: 0 }));
            return true;

        case "flushQueueNow":
            flushQueue({ force: true }).then(sendResponse);
            return true;

        case "getCached": {
            const n = Core.normalizeUrl(message.url);
            const c = n.ok ? verdictCache.get(n.normalized) : null;
            sendResponse(c ? c.data : null);
            return false;
        }

        case "updateStats": {
            const tabId = sender.tab?.id;
            if (tabId != null) { tabStats.set(tabId, message.stats); updateBadge(tabId, message.stats); }
            sendResponse({ ok: true });
            return false;
        }

        case "getStats":
            sendResponse(tabStats.get(message.tabId) || { total: 0, phishing: 0, suspicious: 0, safe: 0 });
            return false;

        case "trustDomain":
            ready.then(async () => {
                if (!state.trusted.includes(message.domain)) state.trusted.push(message.domain);
                await chrome.storage.local.set({ trustedDomains: state.trusted });
                sendResponse({ ok: true });
            });
            return true;

        case "untrustDomain":
            ready.then(async () => {
                state.trusted = state.trusted.filter(d => d !== message.domain);
                await chrome.storage.local.set({ trustedDomains: state.trusted });
                sendResponse({ ok: true });
            });
            return true;

        case "getTrustedDomains":
            ready.then(() => sendResponse(state.trusted));
            return true;

        case "getRecentScans":
            chrome.storage.local.get("recentScans", ({ recentScans }) => sendResponse(recentScans || []));
            return true;

        case "bypassUrl":
            bypassedUrls.set(message.url, Date.now() + 60_000);
            sendResponse({ ok: true });
            return false;

        case "reconnectServer":
            (async () => {
                await ready;
                state.serverUrl = resolveServerUrl((await chrome.storage.local.get("phishguardServerUrl")).phishguardServerUrl);
                state.registered = false;
                await chrome.storage.local.set({ pgRegistered: false });
                verdictCache.clear();
                let ok = false;
                try { await register(); await syncRules({ force: true }); ok = true; } catch { /* surfaced via getStatus */ }
                flushQueue({ force: true });
                sendResponse({ ok, serverUrl: state.serverUrl, error: ok ? undefined : state.lastError });
            })();
            return true;
    }
});

// ─── Alarms (survive service-worker suspension; setInterval does not) ───────
function ensureAlarms() {
    for (const [name, period] of [["pg_heartbeat", 0.5], ["pg_event_flush", 0.5], ["pg_rule_sync", 5]]) {
        chrome.alarms.get(name, a => { if (!a) chrome.alarms.create(name, { periodInMinutes: period }); });
    }
}
chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === "pg_heartbeat") sendHeartbeat();
    else if (alarm.name === "pg_event_flush") flushQueue();
    else if (alarm.name === "pg_rule_sync") syncRules().catch(e => { state.lastError = e.message; });
});

// ─── Lifecycle ──────────────────────────────────────────────────────────────
async function bootstrap() {
    await ready;
    ensureAlarms();
    if (!state.serverUrl) return;
    try {
        await ensureRegistered();
        // Cheap, version-gated. Only re-check on wake if the cache is old.
        if (Date.now() - state.rulesSyncedAt > RULES_MAX_AGE_MS || state.rules.version === 0) await syncRules();
    } catch (e) { state.lastError = e.message; }
    flushQueue();
}

chrome.runtime.onStartup.addListener(() => { bootstrap().then(sendHeartbeat); });

chrome.runtime.onInstalled.addListener(() => {
    bootstrap().then(sendHeartbeat);
    try {
        chrome.contextMenus.create({ id: "phishguard-scan-link", title: "🛡 Scan this link with PhishGuard", contexts: ["link"] });
        chrome.contextMenus.create({ id: "phishguard-scan-page", title: "🛡 Scan this page with PhishGuard", contexts: ["page"] });
    } catch { /* already exist */ }
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    const url = info.menuItemId === "phishguard-scan-link" ? info.linkUrl : info.pageUrl;
    if (!url || !tab?.id) return;
    scanUrl(url, "context-menu").then(data => {
        chrome.tabs.sendMessage(tab.id, { action: "showScanToast", url, data }).catch(() => {});
    }).catch(() => {});
});

chrome.tabs.onRemoved.addListener(tabId => {
    tabStats.delete(tabId);
    chrome.action.setBadgeText({ text: "", tabId }).catch(() => {});
    chrome.storage.local.remove(`tabScan_${tabId}`).catch(() => {});
});

// Every service-worker wake (any event) runs this once: it is cheap because
// registration and rule-sync are skipped when already current.
bootstrap();
console.log("PhishGuard service worker active");
