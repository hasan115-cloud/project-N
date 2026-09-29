/*
 * PhishGuard core — SINGLE source of truth for URL normalization and
 * security-rule matching. Loaded by:
 *   - the server (server/*.ts imports it as a CommonJS module), and
 *   - the Chrome extension service worker (importScripts("pg-core.js")).
 *
 * `npm run extension:sync` copies this file to extension/pg-core.js. Never edit
 * the copy; edit this file. Because both sides run the identical code,
 * the extension and the server can never disagree about whether a rule matches.
 *
 * ───────────────────────── RULE PRECEDENCE (deterministic) ────────────────────
 *  1. Only ENABLED rules participate (rule.enabled !== false).
 *  2. Every enabled whitelist AND phishing/blacklist rule that matches the URL
 *     is a candidate.
 *  3. The MOST SPECIFIC candidate wins:
 *       URL-path rules ("example.com/login")  beat  domain rules ("example.com")
 *       and a deeper domain ("login.example.com") beats a shallower one
 *       ("example.com"). Remaining ties fall to longer pattern text.
 *  4. If specificity is still equal, WHITELIST beats PHISHING (an administrator's
 *     explicit allow is respected over an equally-specific block).
 *  5. Final tie-break: oldest rule (createdAt), then id — so the result never
 *     depends on database row order.
 *  If nothing matches, the caller falls back to the safe-list / heuristics.
 *
 *  Matching is host-boundary aware: a rule for "paypal.com" matches
 *  "paypal.com" and "www.paypal.com" but NOT "evil.xyz/paypal.com" or
 *  "notpaypal.com". (Earlier versions used substring matching, which let a
 *  whitelist entry for "paypal.com" whitelist any URL merely CONTAINING it.)
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PGCore = api;
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var MAX_URL_LENGTH = 2048;
  var MAX_PATTERN_LENGTH = 253;

  // ── Safe apex list (used by extension AND server heuristics) ──────────────
  var SAFE_APEX = new Set([
    "google.com", "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com",
    "youtube.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "live.com", "office.com", "azure.com", "outlook.com", "sharepoint.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "linkedin.com", "reddit.com", "tiktok.com", "snapchat.com", "discord.com",
    "github.com", "gitlab.com", "stackoverflow.com", "npmjs.com", "cloudflare.com",
    "wikipedia.org", "wikimedia.org", "amazon.com", "apple.com", "icloud.com",
    "vercel.com", "netlify.com"
  ]);

  var COMPOUND_SLD = new Set(["co", "com", "org", "net", "gov", "ac", "edu", "mil"]);

  function apexDomain(host) {
    if (!host) return "";
    var parts = String(host).split(".");
    if (parts.length >= 3) {
      var secondLast = parts[parts.length - 2];
      var last = parts[parts.length - 1];
      if (COMPOUND_SLD.has(secondLast) && last.length === 2) return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  function isSafeApex(host) {
    return SAFE_APEX.has(host) || SAFE_APEX.has(apexDomain(host));
  }

  // ── URL normalization ─────────────────────────────────────────────────────
  /**
   * Parse + normalize an http(s) URL. Never throws.
   * Returns { ok:false, error } or
   *   { ok:true, href, host, path, normalized }
   * where `normalized` = host[:nonDefaultPort] + path + query, lowercase, no
   * scheme, no "www.", no fragment, no trailing slash, no credentials.
   */
  function normalizeUrl(raw) {
    if (typeof raw !== "string") return { ok: false, error: "URL must be a string" };
    var trimmed = raw.trim();
    if (!trimmed) return { ok: false, error: "URL is empty" };
    if (trimmed.length > MAX_URL_LENGTH) return { ok: false, error: "URL exceeds " + MAX_URL_LENGTH + " characters" };
    var u;
    try { u = new URL(trimmed); } catch (e) { return { ok: false, error: "Malformed URL" }; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return { ok: false, error: "Only http(s) URLs are supported" };
    if (!u.hostname) return { ok: false, error: "URL has no host" };

    var host = u.hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
    var port = u.port ? ":" + u.port : ""; // URL() already drops default ports
    var pathname = u.pathname.replace(/\/+$/, ""); // "/" -> ""
    var rest = (pathname + (u.search || "")).toLowerCase();
    u.username = "";
    u.password = "";
    u.hash = "";
    return {
      ok: true,
      href: u.href,
      host: host,
      path: rest,
      normalized: host + port + rest
    };
  }

  // ── Rule pattern validation / normalization ───────────────────────────────
  /**
   * Validate + normalize an administrator-entered rule pattern.
   * Accepts "example.com", "*.example.com", "https://www.example.com/login".
   * Returns { ok:true, pattern, kind:"domain"|"url" } or { ok:false, error }.
   */
  function normalizePattern(raw) {
    if (typeof raw !== "string") return { ok: false, error: "Pattern must be a string" };
    var p = raw.trim().toLowerCase();
    if (!p) return { ok: false, error: "Pattern is required" };
    if (/\s/.test(p)) return { ok: false, error: "Pattern must not contain spaces" };
    p = p.replace(/^[a-z][a-z0-9+.\-]*:\/\//, "");   // scheme
    p = p.replace(/#.*$/, "");                       // fragment
    p = p.replace(/^\*\./, "");                      // "*.example.com" -> "example.com"
    p = p.replace(/^www\./, "");
    p = p.replace(/\/+$/, "");                       // trailing slash(es)
    if (!p) return { ok: false, error: "Pattern is empty after normalization" };
    if (p.length > MAX_PATTERN_LENGTH) return { ok: false, error: "Pattern is too long" };
    if (p.indexOf("*") !== -1) return { ok: false, error: "Wildcards are only supported as a leading \"*.\"" };

    var m = p.match(/^([^\/?]+)(.*)$/);
    var hostPart = m ? m[1] : p;
    var rest = m ? m[2] : "";
    // Let the URL parser validate/IDNA-encode the host portion.
    var hostname;
    try {
      var probe = new URL("http://" + hostPart);
      hostname = probe.hostname.toLowerCase();
      if (probe.username || probe.password) return { ok: false, error: "Credentials are not allowed in a pattern" };
    } catch (e) { return { ok: false, error: "Invalid host in pattern" }; }
    if (!/^[a-z0-9.\-:]+$/.test(hostname) || hostname.charAt(0) === "." || hostname.slice(-1) === ".") {
      return { ok: false, error: "Invalid host in pattern" };
    }
    if (hostname.indexOf(".") === -1 && !/^\[/.test(hostname)) {
      return { ok: false, error: "Pattern must be a full domain (e.g. example.com), not a bare label like \"" + hostname + "\"" };
    }
    // Reject bare public suffix-like patterns that would match half the internet.
    if (/^(com|org|net|edu|gov|co\.[a-z]{2}|com\.[a-z]{2}|org\.[a-z]{2}|net\.[a-z]{2}|ac\.[a-z]{2})$/.test(hostname)) {
      return { ok: false, error: "Pattern is too broad" };
    }
    var normalized = hostname + rest;
    return { ok: true, pattern: normalized, kind: rest ? "url" : "domain" };
  }

  // ── Matching ──────────────────────────────────────────────────────────────
  function hostMatches(host, patternHost) {
    return host === patternHost || (host.length > patternHost.length && host.slice(-(patternHost.length + 1)) === "." + patternHost);
  }

  /** Does a NORMALIZED url (from normalizeUrl) match a NORMALIZED pattern? */
  function patternMatches(norm, pattern) {
    var m = pattern.match(/^([^\/?]+)(.*)$/);
    var pHost = m ? m[1] : pattern;
    var pRest = m ? m[2] : "";
    // Compare host without any :port on the URL side for domain rules.
    var urlHost = norm.host;
    if (!pRest) return hostMatches(urlHost, pHost);
    if (!hostMatches(urlHost, pHost)) return false;
    if (norm.path.indexOf(pRest) !== 0) return false;
    var next = norm.path.charAt(pRest.length);
    return next === "" || next === "/" || next === "?" || pRest.slice(-1) === "/" || pRest.slice(-1) === "?";
  }

  function specificity(pattern) {
    var m = pattern.match(/^([^\/?]+)(.*)$/);
    var pHost = m ? m[1] : pattern;
    var pRest = m ? m[2] : "";
    var labels = pHost.split(".").length;
    return (pRest ? 100000 : 0) + labels * 1000 + pattern.length;
  }

  function ruleOf(type, r) {
    return {
      type: type,
      id: r.id,
      pattern: String(r.pattern || "").toLowerCase(),
      createdAt: r.createdAt || "",
      raw: r
    };
  }

  /**
   * Evaluate a URL against the rule sets using the precedence documented at
   * the top of this file. `rules` = { whitelist: Rule[], phishing: Rule[] }.
   * Returns null (no rule matched) or
   *   { type:"WHITELIST"|"PHISHING", action:"ALLOWED"|"BLOCKED",
   *     ruleId, pattern, rule }
   */
  function evaluateRules(url, rules) {
    var norm = typeof url === "object" && url && url.ok ? url : normalizeUrl(url);
    if (!norm.ok || !rules) return null;
    var candidates = [];
    (rules.whitelist || []).forEach(function (r) {
      if (r && r.enabled !== false && r.pattern) candidates.push(ruleOf("WHITELIST", r));
    });
    (rules.phishing || []).forEach(function (r) {
      if (r && r.enabled !== false && r.pattern) candidates.push(ruleOf("PHISHING", r));
    });
    var best = null;
    for (var i = 0; i < candidates.length; i++) {
      var c = candidates[i];
      if (!patternMatches(norm, c.pattern)) continue;
      c.spec = specificity(c.pattern);
      if (!best || beats(c, best)) best = c;
    }
    if (!best) return null;
    return {
      type: best.type,
      action: best.type === "WHITELIST" ? "ALLOWED" : "BLOCKED",
      ruleId: best.id,
      pattern: best.pattern,
      rule: best.raw
    };
  }

  function beats(a, b) {
    if (a.spec !== b.spec) return a.spec > b.spec;
    if (a.type !== b.type) return a.type === "WHITELIST";
    if (a.createdAt !== b.createdAt) return a.createdAt < b.createdAt;
    return String(a.id) < String(b.id);
  }

  /** Hosts the extension/server must never record as browsing history. */
  function isInternalHost(host, extraHosts) {
    if (!host) return true;
    if (/(^|\.)supabase\.(co|com|in|net)$/.test(host)) return true;
    if (extraHosts) {
      for (var i = 0; i < extraHosts.length; i++) {
        var h = extraHosts[i];
        if (h && (host === h || host.slice(-(h.length + 1)) === "." + h)) return true;
      }
    }
    return false;
  }

  return {
    MAX_URL_LENGTH: MAX_URL_LENGTH,
    SAFE_APEX: SAFE_APEX,
    apexDomain: apexDomain,
    isSafeApex: isSafeApex,
    normalizeUrl: normalizeUrl,
    normalizePattern: normalizePattern,
    patternMatches: patternMatches,
    evaluateRules: evaluateRules,
    isInternalHost: isInternalHost
  };
});
