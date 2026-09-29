import express, { NextFunction, Request, RequestHandler, Response } from "express";
import cors from "cors";
import crypto from "crypto";
import core, { NormalizedUrl } from "../shared/pgcore.cjs";
import { db } from "./db";
import { classifyUrl, ScanResult } from "./detector";
import { generateExtensionZip } from "./extensionPackager";
import { config } from "./config";
import { AuthedClient, DetectionInput, HttpError } from "./dbTypes";
import { RuleType } from "./types";

/**
 * PhishGuard API.
 *
 * Two audiences, two auth models:
 *
 *  EXTENSION endpoints  →  per-system credentials. Each installed extension
 *    generates an id + a random secret, registers once, and afterwards sends
 *    `X-Client-ID` + `Authorization: Bearer <secret>`. Only the SHA-256 of the
 *    secret is stored. The client id used for every write comes from the
 *    authenticated identity, never from the request body, so one extension can
 *    never write into (or overwrite) another system's records.
 *
 *  DASHBOARD endpoints  →  no login screen (product decision). If you set
 *    DASHBOARD_BASIC_AUTH="user:password" they are protected by HTTP Basic
 *    auth (native browser prompt). Strongly recommended for production.
 *
 * The Supabase service-role key is never used or needed: the server talks to
 * Postgres directly with DATABASE_URL, and nothing privileged is ever sent to
 * the browser or the extension.
 */

const MAX_EVENTS_PER_BATCH = 200;
const MAX_BULK_URLS = 50;

// ── small validation helpers ────────────────────────────────────────────────
const CLIENT_ID_RE = /^[A-Za-z0-9_.\-]{8,80}$/;
const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

function safeEqual(a: string, b: string): boolean {
  const ha = crypto.createHash("sha256").update(a).digest();
  const hb = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function cleanText(v: unknown, max: number): string | undefined {
  if (typeof v !== "string") return undefined;
  // eslint-disable-next-line no-control-regex
  const t = v.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max);
  return t || undefined;
}

function bearer(req: Request): string {
  const h = req.get("authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function clientIp(req: Request): string | undefined {
  const raw =
    req.get("x-nf-client-connection-ip") ||
    (req.get("x-forwarded-for") || "").split(",")[0] ||
    req.socket.remoteAddress ||
    "";
  return cleanText(raw, 64);
}

function requestOrigin(req: Request): string {
  if (config.publicOrigin) return config.publicOrigin;
  const host = req.get("x-forwarded-host") || req.get("host") || "";
  const isLocal = /^(localhost|127\.0\.0\.1)(:|$)/.test(host);
  const proto = req.get("x-forwarded-proto") || (isLocal ? req.protocol : "https");
  return `${proto.split(",")[0]}://${host}`;
}

function internalHosts(req: Request): string[] {
  const out: string[] = [];
  try { out.push(new URL(requestOrigin(req)).hostname); } catch { /* ignore */ }
  const host = (req.get("host") || "").split(":")[0];
  if (host) out.push(host);
  return out;
}

const wrap = (fn: (req: Request, res: Response) => Promise<any>): RequestHandler =>
  (req, res, next) => { fn(req, res).catch(next); };

interface ClientRequest extends Request { client?: AuthedClient }

// ── auth middleware ─────────────────────────────────────────────────────────
const requireClient: RequestHandler = (req, res, next) => {
  (async () => {
    const id = (req.get("x-client-id") || "").trim();
    const secret = bearer(req);
    if (!CLIENT_ID_RE.test(id) || secret.length < 32) {
      throw new HttpError(401, "Missing or invalid extension credentials", "unauthorized");
    }
    const client = await db.authenticateClient(id, sha256(secret));
    if (!client) {
      // Either the system was removed from the dashboard or the secret is wrong.
      throw new HttpError(401, "Unknown system or invalid credentials — re-register the extension", "unauthorized");
    }
    (req as ClientRequest).client = client;
    next();
  })().catch(next);
};

const dashboardAuth: RequestHandler = (req, res, next) => {
  const cred = config.dashboardBasicAuth;
  if (!cred) return next();
  const h = req.get("authorization") || "";
  const m = h.match(/^Basic\s+(.+)$/i);
  let ok = false;
  if (m) {
    try { ok = safeEqual(Buffer.from(m[1], "base64").toString("utf8"), cred); } catch { ok = false; }
  }
  if (ok) return next();
  res.setHeader("WWW-Authenticate", 'Basic realm="PhishGuard Dashboard", charset="UTF-8"');
  res.status(401).json({ error: "Authentication required", code: "unauthorized" });
};

const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
};

// ── decision → wire format ──────────────────────────────────────────────────
function decisionPayload(r: ScanResult) {
  return {
    verdict: r.verdict,
    action: r.action,
    score: r.score,
    risk_score: r.score,
    domain: r.domain,
    reasons: r.reasons,
    whitelisted: r.whitelisted,
    policyMatched: r.policyMatched,
    ruleTriggered: r.ruleType !== null,
    ruleType: r.ruleType,
    matchedRule: r.matchedRuleId ? { id: r.matchedRuleId, pattern: r.matchedPattern, type: r.ruleType } : null,
    decisionSource: r.decisionSource
  };
}

function toDetection(
  client: AuthedClient, rawUrl: string, norm: NormalizedUrl, r: ScanResult,
  source: string, eventId?: string, observedAt?: string
): DetectionInput {
  return {
    eventId,
    client,
    url: rawUrl.trim().slice(0, core.MAX_URL_LENGTH),
    normalizedUrl: norm.normalized,
    domain: r.domain,
    classification: r.verdict,
    verdict: r.action,
    score: r.score,
    reason: r.reasons.join("; ") || "Clean analysis",
    source,
    ruleType: r.ruleType,
    matchedRuleId: r.matchedRuleId,
    matchedPattern: r.matchedPattern,
    decisionSource: r.decisionSource,
    observedAt,
    // A BLOCKED outcome (administrator rule OR high-confidence heuristic) raises
    // exactly one alert, atomically with the history row, deduped by eventId.
    alertReasons: r.action === "BLOCKED" ? r.reasons : undefined
  };
}

const SOURCE_RE = /^[a-z0-9][a-z0-9_.\-]{0,39}$/i;
const cleanSource = (v: unknown, fallback: string) =>
  typeof v === "string" && SOURCE_RE.test(v) ? v : fallback;

// ── rule input parsing ──────────────────────────────────────────────────────
function parseRuleBody(type: RuleType, body: any, partial: boolean) {
  const out: { pattern?: string; description?: string; reason?: string; severity?: "HIGH" | "CRITICAL"; enabled?: boolean } = {};
  if (!body || typeof body !== "object") throw new HttpError(400, "JSON body required", "invalid_payload");
  if (body.pattern !== undefined || !partial) {
    const p = core.normalizePattern(body.pattern);
    if (!p.ok) throw new HttpError(400, p.error, "invalid_pattern");
    out.pattern = p.pattern;
  }
  if (body.enabled !== undefined) {
    if (typeof body.enabled !== "boolean") throw new HttpError(400, "enabled must be true or false", "invalid_payload");
    out.enabled = body.enabled;
  }
  if (type === "WHITELIST") {
    if (body.description !== undefined) out.description = cleanText(body.description, 200) || "Whitelisted domain";
  } else {
    if (body.reason !== undefined) out.reason = cleanText(body.reason, 200) || "Threat rule";
    if (body.severity !== undefined) {
      if (body.severity !== "HIGH" && body.severity !== "CRITICAL") throw new HttpError(400, "severity must be HIGH or CRITICAL", "invalid_payload");
      out.severity = body.severity;
    } else if (!partial) out.severity = "HIGH";
  }
  return out;
}

export function createApiApp() {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", true);

  // Chrome extensions call from their service worker (host_permissions bypass
  // CORS) and the dashboard is same-origin, so browsers other than those two
  // callers are simply not granted CORS access.
  app.use(cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (origin.startsWith("chrome-extension://")) return cb(null, true);
      try {
        const allowed = new Set<string>();
        if (config.publicOrigin) allowed.add(new URL(config.publicOrigin).origin);
        if (allowed.has(new URL(origin).origin)) return cb(null, true);
        if (/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) && process.env.NODE_ENV !== "production") return cb(null, true);
      } catch { /* fallthrough */ }
      cb(null, false);
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Client-ID", "X-Enrollment-Key"],
    maxAge: 86400
  }));

  app.use(express.json({ limit: "1mb" }));

  const router = express.Router();

  // ════════════════════════ public / diagnostics ═════════════════════════════
  router.get("/health", noStore, wrap(async (_req, res) => {
    try {
      const { schemaVersion } = await db.ping();
      res.json({ status: "ok", service: "PhishGuard", database: "up", schemaVersion, timestamp: new Date().toISOString() });
    } catch (err: any) {
      console.error("GET /health: database check failed:", err?.message || err);
      const status = err instanceof HttpError ? err.status : 503;
      res.status(status).json({
        status: "error", service: "PhishGuard", database: "down",
        code: err?.code || "database_unavailable",
        message: err instanceof HttpError ? err.message : "Database unreachable",
        timestamp: new Date().toISOString()
      });
    }
  }));

  router.get("/info", noStore, (req, res) => {
    res.json({
      serverUrl: requestOrigin(req),
      version: config.version,
      status: "operational",
      dashboardProtected: Boolean(config.dashboardBasicAuth),
      enrollmentKeyRequired: Boolean(config.enrollmentKey)
    });
  });

  // ════════════════════════ EXTENSION endpoints ══════════════════════════════

  // Register (idempotent). Identity = (clientId, secret). Same pair → same row,
  // any number of times; an existing id with a different secret is refused.
  router.post("/clients/register", noStore, wrap(async (req, res) => {
    const b = req.body || {};
    const clientId = typeof b.clientId === "string" ? b.clientId.trim() : "";
    if (!CLIENT_ID_RE.test(clientId)) throw new HttpError(400, "clientId must be 8-80 characters (letters, digits, . _ -)", "invalid_payload");
    const secret = bearer(req);
    if (secret.length < 32 || secret.length > 200) throw new HttpError(401, "A client secret of at least 32 characters is required", "unauthorized");

    if (config.enrollmentKey && !(await db.clientHasCredentials(clientId))) {
      const given = req.get("x-enrollment-key") || "";
      if (!given || !safeEqual(given, config.enrollmentKey)) {
        throw new HttpError(403, "A valid enrollment key is required to enroll a new system", "enrollment_key_required");
      }
    }

    const client = await db.registerClient({
      clientId,
      clientName: cleanText(b.clientName, 80),
      os: cleanText(b.os, 40),
      browser: cleanText(b.browser, 40),
      platform: cleanText(b.platform, 40),
      extensionVersion: cleanText(b.extensionVersion, 20),
      ip: clientIp(req)
    }, sha256(secret));
    if (!client) throw new HttpError(401, "This system id is already registered with different credentials", "id_taken");

    const rules = await db.getActiveRules();
    res.json({ success: true, client, rulesVersion: rules.version, serverTime: new Date().toISOString() });
  }));

  router.post("/clients/heartbeat", noStore, requireClient, wrap(async (req, res) => {
    const client = (req as ClientRequest).client!;
    const b = req.body || {};
    let stats: Record<string, number> | undefined;
    if (b.stats && typeof b.stats === "object") {
      stats = {};
      for (const k of ["total", "phishing", "suspicious", "safe"]) {
        const n = Number((b.stats as any)[k]);
        if (Number.isFinite(n) && n >= 0) stats[k] = Math.floor(n);
      }
    }
    await db.heartbeatClient(client.id, stats, { ip: clientIp(req), extensionVersion: cleanText(b.extensionVersion, 20) });
    const rules = await db.getActiveRules();
    // Only the VERSION is returned; the extension downloads rules only if it changed.
    res.json({ success: true, rulesVersion: rules.version, serverTime: new Date().toISOString() });
  }));

  router.get("/extension/rules", noStore, requireClient, wrap(async (req, res) => {
    const rules = await db.getActiveRules();
    const since = parseInt(String(req.query.since ?? ""), 10);
    if (Number.isFinite(since) && since === rules.version) {
      return res.json({ changed: false, version: rules.version });
    }
    res.json({
      changed: true,
      version: rules.version,
      whitelist: rules.whitelist.map(r => ({ id: r.id, pattern: r.pattern, createdAt: r.createdAt })),
      phishing: rules.phishing.map(r => ({ id: r.id, pattern: r.pattern, severity: r.severity, reason: r.reason, createdAt: r.createdAt }))
    });
  }));

  // Real-time decision for ONE URL the user is navigating to / manually scanning.
  router.post("/scan", noStore, requireClient, wrap(async (req, res) => {
    const client = (req as ClientRequest).client!;
    const b = req.body || {};
    const norm = core.normalizeUrl(b.url);
    if (!norm.ok) throw new HttpError(400, norm.error, "invalid_url");

    const rules = await db.getActiveRules();
    const result = classifyUrl(norm, rules);

    let recorded = false, duplicate = false, ignored = false;
    if (core.isInternalHost(norm.host, internalHosts(req))) {
      ignored = true; // never log the dashboard / API / Supabase itself
    } else if (b.record !== false) {
      const eventId = typeof b.eventId === "string" && b.eventId.length <= 100 ? b.eventId : undefined;
      const [{ wasNew }] = await db.recordDetections([
        toDetection(client, b.url, norm, result, cleanSource(b.source, "extension"), eventId, typeof b.observedAt === "string" ? b.observedAt : undefined)
      ]);
      recorded = true; duplicate = !wasNew;
    }
    res.json({ ...decisionPayload(result), rulesVersion: rules.version, recorded, duplicate, ignored });
  }));

  // Classification ONLY — used for in-page link badges. Deliberately NOT written
  // to URL History: the user has not visited these links.
  router.post("/bulk-scan", noStore, requireClient, wrap(async (req, res) => {
    const urls = req.body?.urls;
    if (!Array.isArray(urls) || urls.length === 0 || urls.length > MAX_BULK_URLS) {
      throw new HttpError(400, `urls must be an array of 1-${MAX_BULK_URLS} items`, "invalid_payload");
    }
    const rules = await db.getActiveRules();
    const results = urls.map(u => {
      const norm = core.normalizeUrl(u);
      if (!norm.ok) return { url: typeof u === "string" ? u.slice(0, 200) : "", verdict: "ERROR", error: norm.error };
      return { url: u, ...decisionPayload(classifyUrl(norm, rules)) };
    });
    res.json({ results, rulesVersion: rules.version });
  }));

  // Batch ingest of observed navigations (extension's durable offline queue).
  router.post("/url-events", noStore, requireClient, wrap(async (req, res) => {
    const client = (req as ClientRequest).client!;
    const events = req.body?.events;
    if (!Array.isArray(events) || events.length > MAX_EVENTS_PER_BATCH) {
      throw new HttpError(400, `events must be an array of at most ${MAX_EVENTS_PER_BATCH} items`, "invalid_payload");
    }
    const rules = await db.getActiveRules();
    const internal = internalHosts(req);

    const inputs: DetectionInput[] = [];
    const inputIds: string[] = [];
    const ackInvalid: string[] = [];
    const ackIgnored: string[] = [];
    let invalid = 0, ignored = 0;

    for (const e of events) {
      const eventId = typeof e?.eventId === "string" && e.eventId.length > 0 && e.eventId.length <= 100 ? e.eventId : null;
      const norm = core.normalizeUrl(e?.url);
      if (!eventId || !norm.ok) {
        invalid++;
        if (eventId) ackInvalid.push(eventId); // can never become valid → drop from the client's queue
        continue;
      }
      if (core.isInternalHost(norm.host, internal)) {
        ignored++; ackIgnored.push(eventId); continue;
      }
      const result = classifyUrl(norm, rules);
      inputs.push(toDetection(client, e.url, norm, result, cleanSource(e.source, "extension-navigation"), eventId, typeof e.observedAt === "string" ? e.observedAt : undefined));
      inputIds.push(eventId);
    }

    // One transaction: either the whole batch (events + their alerts) is stored
    // or none of it is → the extension simply retries; idempotency makes that safe.
    const outcomes = await db.recordDetections(inputs);
    const acceptedIds: string[] = [];
    const duplicateIds: string[] = [];
    outcomes.forEach((o, i) => (o.wasNew ? acceptedIds : duplicateIds).push(inputIds[i]));

    res.json({
      success: true,
      accepted: acceptedIds.length,
      duplicates: duplicateIds.length,
      ignored,
      invalid,
      acknowledgedIds: [...acceptedIds, ...duplicateIds, ...ackIgnored, ...ackInvalid],
      rulesVersion: rules.version
    });
  }));

  // Alert for an event that is NOT a navigation (e.g. blocked in-page link click).
  router.post("/threats/alert", noStore, requireClient, wrap(async (req, res) => {
    const client = (req as ClientRequest).client!;
    const b = req.body || {};
    const norm = core.normalizeUrl(b.url);
    if (!norm.ok) throw new HttpError(400, norm.error, "invalid_url");
    const eventId = typeof b.eventId === "string" && b.eventId.length > 0 && b.eventId.length <= 100 ? b.eventId : `alert-${crypto.randomUUID()}`;
    const reasons = Array.isArray(b.reasons) ? b.reasons.slice(0, 10).map((r: unknown) => cleanText(r, 300)).filter(Boolean) as string[] : [];
    const score = typeof b.score === "number" && b.score >= 0 && b.score <= 1 ? b.score : 0.9;
    const out = await db.recordAlert({
      eventId, client, url: String(b.url).trim().slice(0, core.MAX_URL_LENGTH), domain: norm.host, score,
      reasons: reasons.length ? reasons : ["Phishing site intercepted"], source: cleanSource(b.source, "extension-block")
    });
    res.json({ success: true, wasNew: out.wasNew, alert: out.alert });
  }));

  // ════════════════════════ DASHBOARD endpoints ══════════════════════════════
  // Middleware is attached PER ROUTE (not router-wide) so unknown paths still 404
  // and, in self-hosted mode, static assets are not run through auth/no-store.
  const D = [dashboardAuth, noStore];
  const dash = router;

  dash.get("/clients", ...D, wrap(async (_req, res) => {
    const clients = await db.getClients();
    res.json({ clients, count: clients.length });
  }));

  dash.get("/clients/:id", ...D, wrap(async (req, res) => {
    const client = await db.getClientById(req.params.id);
    if (!client) throw new HttpError(404, "System not found", "not_found");
    const [{ events, total, hasMore }, alerts] = await Promise.all([
      db.getUrlEvents({ clientId: req.params.id, limit: 200 }),
      db.getThreatAlerts(req.params.id, 200)
    ]);
    res.json({ client, events, eventsTotal: total, eventsHasMore: hasMore, alerts });
  }));

  dash.delete("/clients/:id", ...D, wrap(async (req, res) => {
    if (!(await db.deleteClient(req.params.id))) throw new HttpError(404, "System not found", "not_found");
    res.json({ success: true, message: "System unenrolled; its history and alerts were removed from the database" });
  }));

  dash.get("/threats", ...D, wrap(async (req, res) => {
    const clientId = typeof req.query.clientId === "string" ? req.query.clientId.slice(0, 100) : undefined;
    const alerts = await db.getThreatAlerts(clientId);
    res.json({ alerts, count: alerts.length });
  }));

  dash.patch("/threats/:id", ...D, wrap(async (req, res) => {
    const status = req.body?.status;
    if (!["ACKNOWLEDGED", "RESOLVED", "ACTIVE"].includes(status)) throw new HttpError(400, "status must be ACKNOWLEDGED, RESOLVED or ACTIVE", "invalid_payload");
    if (!(await db.updateThreatAlertStatus(req.params.id, status))) throw new HttpError(404, "Alert not found", "not_found");
    res.json({ success: true });
  }));

  // Rules — persisted in Supabase; the extension picks changes up via the rules version.
  dash.get("/rules", ...D, wrap(async (_req, res) => {
    res.json(await db.getRules());
  }));

  (["whitelist", "phishing"] as const).forEach(path => {
    const type: RuleType = path === "whitelist" ? "WHITELIST" : "PHISHING";
    dash.post(`/rules/${path}`, ...D, wrap(async (req, res) => {
      const rule = await db.addRule(type, parseRuleBody(type, req.body, false) as any);
      res.status(201).json({ success: true, rule });
    }));
    const update = wrap(async (req, res) => {
      const patch = parseRuleBody(type, req.body, true);
      const rule = await db.updateRule(type, req.params.id, patch);
      if (!rule) throw new HttpError(404, "Rule not found", "not_found");
      res.json({ success: true, rule });
    });
    dash.patch(`/rules/${path}/:id`, ...D, update);
    dash.put(`/rules/${path}/:id`, ...D, update);
    dash.delete(`/rules/${path}/:id`, ...D, wrap(async (req, res) => {
      if (!(await db.deleteRule(type, req.params.id))) throw new HttpError(404, "Rule not found", "not_found");
      res.json({ success: true });
    }));
  });

  dash.get("/events", ...D, wrap(async (req, res) => {
    const q = req.query;
    const classification = typeof q.classification === "string" ? q.classification : undefined;
    if (classification && !["ALL", "SAFE", "SUSPICIOUS", "PHISHING"].includes(classification)) {
      throw new HttpError(400, "classification must be ALL, SAFE, SUSPICIOUS or PHISHING", "invalid_payload");
    }
    const num = (v: unknown) => (typeof v === "string" && /^\d{1,7}$/.test(v) ? parseInt(v, 10) : undefined);
    res.json(await db.getUrlEvents({
      clientId: typeof q.clientId === "string" ? q.clientId.slice(0, 100) : undefined,
      classification,
      search: typeof q.search === "string" ? q.search.slice(0, 200) : undefined,
      limit: num(q.limit),
      offset: num(q.offset)
    }));
  }));

  dash.get("/stats", ...D, wrap(async (req, res) => {
    res.json(await db.getDashboardStats(typeof req.query.clientId === "string" ? req.query.clientId.slice(0, 100) : undefined));
  }));

  dash.get("/reports", ...D, wrap(async (req, res) => {
    const clientId = typeof req.query.clientId === "string" ? req.query.clientId.slice(0, 100) : undefined;
    if (clientId && clientId !== "ALL" && !(await db.clientExists(clientId))) throw new HttpError(404, "System not found", "not_found");
    res.json(await db.getReportData(clientId));
  }));

  dash.get(["/download-extension", "/extension/download"], ...D, wrap(async (req, res) => {
    const origin = requestOrigin(req);
    const zip = await generateExtensionZip(origin, config.enrollmentKey || undefined);
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", 'attachment; filename="phishguard-extension.zip"');
    res.setHeader("Content-Length", zip.length);
    res.send(zip);
  }));

  // Reachable as /api/*, as the raw Netlify function path, and (defensively) with the
  // prefix stripped, because Netlify rewrites can deliver any of the three.
  app.use("/api", router);
  app.use("/.netlify/functions/api", router);
  app.use("/", router);
  app.use("/api", (_req, res) => { res.status(404).json({ error: "Not found", code: "not_found" }); });

  // ── central error handler ─────────────────────────────────────────────────
  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    if (err instanceof HttpError) {
      if (err.status >= 500) console.error(`${req.method} ${req.path} → ${err.status} ${err.code}: ${err.message}`);
      return res.status(err.status).json({ error: err.message, code: err.code });
    }
    if (err?.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON body", code: "invalid_payload" });
    if (err?.type === "entity.too.large") return res.status(413).json({ error: "Request body too large", code: "payload_too_large" });
    const ref = crypto.randomBytes(4).toString("hex");
    console.error(`[${ref}] ${req.method} ${req.path} failed:`, err);
    const dbDown = ["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "ENOTFOUND", "57P01", "53300", "28P01", "3D000"].includes(err?.code) ||
      /Connection terminated|timeout exceeded when trying to connect|password authentication failed/i.test(String(err?.message));
    if (dbDown) {
      return res.status(503).json({ error: "Database unavailable — check DATABASE_URL and that the Supabase project is running", code: "database_unavailable", ref });
    }
    res.status(500).json({ error: "Internal server error", code: "internal_error", ref });
  });

  return app;
}
