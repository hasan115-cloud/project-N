import { Pool, PoolClient } from "pg";
import crypto from "crypto";
import core, { NormalizedUrl } from "../shared/pgcore.cjs";
import {
  EnrolledClient,
  ONLINE_THRESHOLD_MS,
  PhishingRule,
  RuleSet,
  RuleType,
  ThreatAlert,
  UrlEvent,
  WhitelistRule
} from "./types";
import {
  AnyRule,
  AuthedClient,
  DashboardStatsResult,
  DetectionInput,
  HttpError,
  IDatabase,
  ReportDataResult,
  RuleInput,
  UrlEventFilters,
  UrlEventsResult
} from "./dbTypes";
import { config } from "./config";

/**
 * PostgreSQL (Supabase) implementation — the ONLY storage backend.
 *
 *  - The schema is owned by supabase/schema.sql. This class NEVER runs DDL.
 *    On first use it verifies the schema version and, if the SQL file has not
 *    been applied, every request fails with HTTP 503 and an actionable message
 *    (instead of the old behaviour of silently using a per-instance file).
 *  - No query result is ever swallowed into an empty array: a database error is
 *    thrown, logged by the route, and returned as an HTTP error.
 *  - Aggregates (stats, reports, per-system counts) are computed in SQL with
 *    indexes — nothing loads the whole history into memory.
 */

const DEFAULT_PAGE = 200;
const MAX_PAGE = 1000;

/** Strip sslmode/ssl params from the URL and decide TLS explicitly (see below). */
function prepareConnection(connectionString: string): { connectionString: string; ssl: false | { rejectUnauthorized: boolean } } {
  let disableSsl = false;
  let cs = connectionString;
  try {
    const u = new URL(connectionString);
    const mode = (u.searchParams.get("sslmode") || "").toLowerCase();
    if (mode === "disable") disableSsl = true;
    // pg >= 8.16 treats sslmode=require as verify-full, which rejects the
    // Supabase pooler certificate chain. We control TLS ourselves instead.
    for (const k of ["sslmode", "sslcert", "sslkey", "sslrootcert", "ssl", "uselibpqcompat"]) u.searchParams.delete(k);
    cs = u.toString();
    if (/^(localhost|127\.0\.0\.1|\[::1\])$/i.test(u.hostname)) disableSsl = true;
  } catch { /* leave as-is; pg will report a clear parse error */ }
  // Supabase (and every managed Postgres) requires TLS. The connection is
  // encrypted; the chain is not pinned because Node's CA bundle does not always
  // contain Supabase's issuer. To pin it, download the CA from
  // Supabase → Database → SSL and pass it as `ca`.
  return { connectionString: cs, ssl: disableSsl ? false : { rejectUnauthorized: false } };
}

function newId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function isTransient(err: any): boolean {
  const code = err?.code || "";
  const msg = String(err?.message || "");
  return (
    ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EPIPE", "57P01", "57P02", "57P03", "08000", "08003", "08006", "53300"].includes(code) ||
    /Connection terminated|connection timeout|timeout exceeded when trying to connect|server closed the connection/i.test(msg)
  );
}

export class PostgresDatabase implements IDatabase {
  private pool: Pool;
  private schemaOk = false;
  private activeRulesCache: { version: number; rules: RuleSet } | null = null;

  constructor(connectionString: string) {
    const conn = prepareConnection(connectionString);
    this.pool = new Pool({
      connectionString: conn.connectionString,
      ssl: conn.ssl,
      // Serverless: a few short-lived connections per instance. Netlify runs
      // many instances; Supabase's transaction pooler (port 6543) multiplexes.
      max: 4,
      idleTimeoutMillis: 20_000,
      connectionTimeoutMillis: 8_000,
      statement_timeout: 15_000,
      application_name: "phishguard-api"
    });
    // An idle-client error must never crash the process.
    this.pool.on("error", err => console.error("[pg] idle client error:", err.message));
  }

  // ── plumbing ──────────────────────────────────────────────────────────────
  private async ensureSchema(): Promise<void> {
    if (this.schemaOk) return;
    let row: any;
    try {
      const r = await this.pool.query(`SELECT value FROM schema_meta WHERE key = 'schema_version'`);
      row = r.rows[0];
    } catch (err: any) {
      if (err?.code === "42P01") {
        throw new HttpError(503, "Database schema is not installed. Run supabase/schema.sql in the Supabase SQL Editor.", "schema_missing");
      }
      throw err;
    }
    if (!row || row.value !== config.schemaVersion) {
      throw new HttpError(
        503,
        `Database schema is out of date (found ${row?.value ?? "none"}, need ${config.schemaVersion}). Re-run supabase/schema.sql in the Supabase SQL Editor.`,
        "schema_outdated"
      );
    }
    this.schemaOk = true;
  }

  private async q(text: string, params: any[] = []): Promise<{ rows: any[] }> {
    await this.ensureSchema();
    try {
      return await this.pool.query(text, params);
    } catch (err: any) {
      if (!isTransient(err)) throw err;
      console.warn("[pg] transient error, retrying once:", err.message);
      return this.pool.query(text, params);
    }
  }

  private async tx<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
    await this.ensureSchema();
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      const out = await fn(c);
      await c.query("COMMIT");
      return out;
    } catch (err) {
      try { await c.query("ROLLBACK"); } catch { /* connection already gone */ }
      throw err;
    } finally {
      c.release();
    }
  }

  public async ping() {
    await this.ensureSchema();
    await this.pool.query("SELECT 1");
    return { schemaVersion: config.schemaVersion };
  }

  // ── mapping helpers (snake_case rows → the app's camelCase shapes) ────────
  private iso(v: any): string { return new Date(v).toISOString(); }

  private mapClient(r: any): EnrolledClient {
    const lastSeen = this.iso(r.last_seen);
    return {
      id: r.id,
      clientName: r.client_name,
      firstSeen: this.iso(r.first_seen),
      lastSeen,
      status: r.status,
      connectionStatus: Date.now() - new Date(lastSeen).getTime() < ONLINE_THRESHOLD_MS ? "ONLINE" : "OFFLINE",
      extensionVersion: r.extension_version || "unknown",
      browser: r.browser || "unknown",
      os: r.os || "unknown",
      platform: r.platform || "unknown",
      ip: r.ip || "unknown",
      telemetryStats: {
        totalScanned: r.t_total ?? 0,
        phishingBlocked: r.t_phishing ?? 0,
        suspiciousDetected: r.t_suspicious ?? 0,
        safeEvaluated: r.t_safe ?? 0
      }
    };
  }

  private mapUrlEvent(r: any): UrlEvent {
    return {
      id: r.id,
      eventId: r.event_id || undefined,
      timestamp: this.iso(r.occurred_at),
      clientId: r.client_id,
      clientName: r.client_name,
      url: r.url,
      normalizedUrl: r.normalized_url || undefined,
      domain: r.domain,
      classification: r.classification,
      verdict: r.verdict,
      score: Number(r.score),
      reason: r.reason,
      source: r.source,
      ruleTriggered: Boolean(r.rule_triggered),
      ruleType: r.rule_type || null,
      matchedRuleId: r.matched_rule_id || null,
      matchedPattern: r.matched_pattern || null,
      decisionSource: r.decision_source || null
    };
  }

  private mapThreatAlert(r: any): ThreatAlert {
    return {
      id: r.id,
      eventId: r.event_id || undefined,
      timestamp: this.iso(r.occurred_at),
      clientId: r.client_id,
      clientName: r.client_name,
      url: r.url,
      domain: r.domain,
      score: Number(r.score),
      reasons: Array.isArray(r.reasons) ? r.reasons : [],
      source: r.source,
      status: r.status,
      matchedRuleId: r.matched_rule_id || null,
      matchedPattern: r.matched_pattern || null,
      ruleType: r.rule_type || null,
      action: r.action || "BLOCKED"
    };
  }

  // Patterns written by older versions may not be in canonical form
  // ("www.x.com", "https://x.com/"). Canonicalize on READ so matching is
  // always consistent, without rewriting stored rows.
  private canonPattern(p: string): string {
    const n = core.normalizePattern(p);
    return n.ok ? n.pattern : String(p).toLowerCase();
  }

  private mapWhitelist = (r: any): WhitelistRule => ({
    id: r.id,
    pattern: this.canonPattern(r.pattern),
    description: r.description || "Whitelisted domain",
    enabled: r.enabled !== false,
    createdAt: this.iso(r.created_at),
    updatedAt: this.iso(r.updated_at || r.created_at),
    addedBy: r.added_by || "Admin"
  });

  private mapPhishing = (r: any): PhishingRule => ({
    id: r.id,
    pattern: this.canonPattern(r.pattern),
    severity: r.severity,
    reason: r.reason || "Threat rule",
    enabled: r.enabled !== false,
    createdAt: this.iso(r.created_at),
    updatedAt: this.iso(r.updated_at || r.created_at),
    addedBy: r.added_by || "Admin"
  });

  // ── rules ─────────────────────────────────────────────────────────────────
  private async rulesVersion(): Promise<number> {
    const { rows } = await this.q(`SELECT version FROM rules_meta WHERE id = 1`);
    return Number(rows[0]?.version ?? 0);
  }

  public async getRules(): Promise<RuleSet> {
    const [w, p, version] = await Promise.all([
      this.q(`SELECT * FROM whitelist_rules ORDER BY created_at ASC, id ASC`),
      this.q(`SELECT * FROM phishing_rules ORDER BY created_at ASC, id ASC`),
      this.rulesVersion()
    ]);
    return { whitelist: w.rows.map(this.mapWhitelist), phishing: p.rows.map(this.mapPhishing), version };
  }

  public async getActiveRules(): Promise<RuleSet> {
    // One primary-key lookup validates the cache; rules are re-read only when
    // the version trigger says something changed (any instance, any writer).
    const version = await this.rulesVersion();
    if (this.activeRulesCache && this.activeRulesCache.version === version) return this.activeRulesCache.rules;
    const all = await this.getRules();
    const rules: RuleSet = {
      whitelist: all.whitelist.filter(r => r.enabled),
      phishing: all.phishing.filter(r => r.enabled),
      version: all.version
    };
    this.activeRulesCache = { version: all.version, rules };
    return rules;
  }

  private table(type: RuleType) {
    return type === "WHITELIST" ? "whitelist_rules" : "phishing_rules";
  }

  public async addRule(type: RuleType, input: RuleInput, addedBy = "Admin"): Promise<AnyRule> {
    const id = newId(type === "WHITELIST" ? "wl" : "ph");
    const res =
      type === "WHITELIST"
        ? await this.q(
            `INSERT INTO whitelist_rules (id, pattern, description, added_by, enabled)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (pattern) DO NOTHING RETURNING *`,
            [id, input.pattern, input.description || "Whitelisted domain", addedBy, input.enabled !== false]
          )
        : await this.q(
            `INSERT INTO phishing_rules (id, pattern, severity, reason, added_by, enabled)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (pattern) DO NOTHING RETURNING *`,
            [id, input.pattern, input.severity || "HIGH", input.reason || "Threat rule", addedBy, input.enabled !== false]
          );
    if (res.rows.length === 0) {
      throw new HttpError(409, `A ${type === "WHITELIST" ? "whitelist" : "phishing"} rule for "${input.pattern}" already exists`, "duplicate_rule");
    }
    return type === "WHITELIST" ? this.mapWhitelist(res.rows[0]) : this.mapPhishing(res.rows[0]);
  }

  public async updateRule(type: RuleType, id: string, patch: Partial<RuleInput>): Promise<AnyRule | null> {
    const t = this.table(type);
    const sets: string[] = [];
    const params: any[] = [id];
    const add = (col: string, val: any) => { params.push(val); sets.push(`${col} = $${params.length}`); };
    if (patch.pattern !== undefined) add("pattern", patch.pattern);
    if (patch.enabled !== undefined) add("enabled", patch.enabled);
    if (type === "WHITELIST") {
      if (patch.description !== undefined) add("description", patch.description);
    } else {
      if (patch.reason !== undefined) add("reason", patch.reason);
      if (patch.severity !== undefined) add("severity", patch.severity);
    }
    if (sets.length === 0) {
      const cur = await this.q(`SELECT * FROM ${t} WHERE id = $1`, [id]);
      if (!cur.rows[0]) return null;
      return type === "WHITELIST" ? this.mapWhitelist(cur.rows[0]) : this.mapPhishing(cur.rows[0]);
    }
    try {
      const { rows } = await this.q(`UPDATE ${t} SET ${sets.join(", ")} WHERE id = $1 RETURNING *`, params);
      if (!rows[0]) return null;
      return type === "WHITELIST" ? this.mapWhitelist(rows[0]) : this.mapPhishing(rows[0]);
    } catch (err: any) {
      if (err?.code === "23505") throw new HttpError(409, `Another rule already uses pattern "${patch.pattern}"`, "duplicate_rule");
      throw err;
    }
  }

  public async deleteRule(type: RuleType, id: string): Promise<boolean> {
    const { rows } = await this.q(`DELETE FROM ${this.table(type)} WHERE id = $1 RETURNING id`, [id]);
    return rows.length > 0;
  }

  // ── systems ───────────────────────────────────────────────────────────────
  private static readonly CLIENT_SELECT = `
    SELECT c.*,
           COALESCE(t.total, 0)      AS t_total,
           COALESCE(t.phishing, 0)   AS t_phishing,
           COALESCE(t.suspicious, 0) AS t_suspicious,
           COALESCE(t.safe, 0)       AS t_safe
    FROM clients c
    LEFT JOIN (
      SELECT client_id,
             COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE classification = 'PHISHING')::int   AS phishing,
             COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
             COUNT(*) FILTER (WHERE classification NOT IN ('PHISHING','SUSPICIOUS'))::int AS safe
      FROM url_events GROUP BY client_id
    ) t ON t.client_id = c.id`;

  public async registerClient(
    p: { clientId: string; clientName?: string; os?: string; browser?: string; platform?: string; extensionVersion?: string; ip?: string },
    secretHash: string
  ): Promise<EnrolledClient | null> {
    const defaultName = `Workstation-${p.clientId.slice(-4).toUpperCase()}`;
    // Idempotent: the same (id, secret) can register any number of times
    // (service-worker restarts, concurrent calls) and always maps to ONE row.
    // A different secret for an existing id updates nothing → 0 rows → null.
    const { rows } = await this.q(
      `INSERT INTO clients (id, client_name, first_seen, last_seen, status, extension_version, browser, os, platform, ip, token_hash)
       VALUES ($1, $2, now(), now(), 'ENROLLED', $3, $4, $5, $6, $7, $8)
       ON CONFLICT (id) DO UPDATE SET
         last_seen = now(),
         token_hash = EXCLUDED.token_hash,
         extension_version = COALESCE(EXCLUDED.extension_version, clients.extension_version),
         browser  = COALESCE(EXCLUDED.browser,  clients.browser),
         os       = COALESCE(EXCLUDED.os,       clients.os),
         platform = COALESCE(EXCLUDED.platform, clients.platform),
         ip       = COALESCE(EXCLUDED.ip,       clients.ip)
       WHERE clients.token_hash IS NULL OR clients.token_hash = EXCLUDED.token_hash
       RETURNING id`,
      [p.clientId, p.clientName || defaultName, p.extensionVersion || null, p.browser || null, p.os || null, p.platform || null, p.ip || null, secretHash]
    );
    if (rows.length === 0) return null;
    return (await this.getClientById(p.clientId)) as EnrolledClient;
  }

  public async authenticateClient(clientId: string, secretHash: string): Promise<AuthedClient | null> {
    const { rows } = await this.q(`SELECT id, client_name, token_hash FROM clients WHERE id = $1`, [clientId]);
    const row = rows[0];
    if (!row || !row.token_hash) return null;
    const a = Buffer.from(row.token_hash);
    const b = Buffer.from(secretHash);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    return { id: row.id, clientName: row.client_name };
  }

  public async clientHasCredentials(clientId: string): Promise<boolean> {
    const { rows } = await this.q(`SELECT token_hash FROM clients WHERE id = $1`, [clientId]);
    return Boolean(rows[0]?.token_hash);
  }

  public async heartbeatClient(clientId: string, stats: Record<string, number> | undefined, patch: { clientName?: string; ip?: string; extensionVersion?: string }) {
    await this.q(
      `UPDATE clients SET
         last_seen = now(),
         status = 'ENROLLED',
         last_stats = COALESCE($2::jsonb, last_stats),
         ip = COALESCE($3, ip),
         extension_version = COALESCE($4, extension_version)
       WHERE id = $1`,
      [clientId, stats ? JSON.stringify(stats) : null, patch.ip || null, patch.extensionVersion || null]
    );
  }

  public async getClients(): Promise<EnrolledClient[]> {
    const { rows } = await this.q(`${PostgresDatabase.CLIENT_SELECT} ORDER BY c.first_seen DESC, c.id`);
    return rows.map(r => this.mapClient(r));
  }

  public async clientExists(id: string): Promise<boolean> {
    const { rows } = await this.q(`SELECT 1 FROM clients WHERE id = $1`, [id]);
    return rows.length > 0;
  }

  public async getClientById(id: string): Promise<EnrolledClient | null> {
    const { rows } = await this.q(`${PostgresDatabase.CLIENT_SELECT} WHERE c.id = $1`, [id]);
    return rows[0] ? this.mapClient(rows[0]) : null;
  }

  public async deleteClient(id: string): Promise<boolean> {
    // FK ON DELETE CASCADE removes this system's history and alerts too.
    const { rows } = await this.q(`DELETE FROM clients WHERE id = $1 RETURNING id`, [id]);
    return rows.length > 0;
  }

  // ── detections (history + alert are one atomic write) ─────────────────────
  private async insertDetection(c: PoolClient, i: DetectionInput): Promise<{ wasNew: boolean }> {
    let occurred = new Date();
    if (i.observedAt) {
      const d = new Date(i.observedAt);
      const now = Date.now();
      // Accept offline-queued observations up to 7 days old; never the future.
      if (!Number.isNaN(d.getTime()) && d.getTime() <= now + 60_000 && d.getTime() >= now - 7 * 86_400_000) {
        occurred = new Date(Math.min(d.getTime(), now));
      }
    }
    const eventId = i.eventId || newId("srv");
    const ins = await c.query(
      `INSERT INTO url_events
         (id, event_id, client_id, client_name, url, normalized_url, domain, classification, verdict, score, reason, source,
          rule_triggered, rule_type, matched_rule_id, matched_pattern, decision_source, occurred_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
       ON CONFLICT (client_id, event_id) WHERE event_id IS NOT NULL DO NOTHING
       RETURNING id`,
      [
        newId("evt"), eventId, i.client.id, i.client.clientName, i.url, i.normalizedUrl, i.domain, i.classification, i.verdict,
        i.score, i.reason, i.source, i.ruleType !== null, i.ruleType, i.matchedRuleId, i.matchedPattern, i.decisionSource, occurred
      ]
    );
    const wasNew = ins.rows.length > 0;
    if (wasNew && i.alertReasons) {
      await c.query(
        `INSERT INTO threat_alerts
           (id, event_id, client_id, client_name, url, domain, score, reasons, source, status,
            matched_rule_id, matched_pattern, rule_type, action, occurred_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE',$10,$11,$12,$13,$14)
         ON CONFLICT (client_id, event_id) WHERE event_id IS NOT NULL DO NOTHING`,
        [
          newId("alt"), eventId, i.client.id, i.client.clientName, i.url, i.domain, i.score, JSON.stringify(i.alertReasons),
          i.source, i.matchedRuleId, i.matchedPattern, i.ruleType, i.verdict, occurred
        ]
      );
    }
    return { wasNew };
  }

  public async recordDetections(inputs: DetectionInput[]): Promise<{ wasNew: boolean }[]> {
    if (inputs.length === 0) return [];
    return this.tx(async c => {
      const out: { wasNew: boolean }[] = [];
      for (const i of inputs) out.push(await this.insertDetection(c, i));
      return out;
    });
  }

  public async recordAlert(a: { eventId: string; client: AuthedClient; url: string; domain: string; score: number; reasons: string[]; source: string }) {
    const { rows } = await this.q(
      `INSERT INTO threat_alerts (id, event_id, client_id, client_name, url, domain, score, reasons, source, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'ACTIVE')
       ON CONFLICT (client_id, event_id) WHERE event_id IS NOT NULL DO NOTHING
       RETURNING *`,
      [newId("alt"), a.eventId, a.client.id, a.client.clientName, a.url, a.domain, a.score, JSON.stringify(a.reasons), a.source]
    );
    if (rows[0]) return { wasNew: true, alert: this.mapThreatAlert(rows[0]) };
    const existing = await this.q(`SELECT * FROM threat_alerts WHERE client_id = $1 AND event_id = $2`, [a.client.id, a.eventId]);
    return { wasNew: false, alert: this.mapThreatAlert(existing.rows[0]) };
  }

  public async getThreatAlerts(clientId?: string, limit = 500): Promise<ThreatAlert[]> {
    const lim = Math.min(Math.max(1, Math.floor(limit)), 2000);
    if (clientId && clientId !== "ALL") {
      const { rows } = await this.q(`SELECT * FROM threat_alerts WHERE client_id = $1 ORDER BY occurred_at DESC, id DESC LIMIT ${lim}`, [clientId]);
      return rows.map(r => this.mapThreatAlert(r));
    }
    const { rows } = await this.q(`SELECT * FROM threat_alerts ORDER BY occurred_at DESC, id DESC LIMIT ${lim}`);
    return rows.map(r => this.mapThreatAlert(r));
  }

  public async updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED" | "ACTIVE") {
    const { rows } = await this.q(`UPDATE threat_alerts SET status = $2 WHERE id = $1 RETURNING id`, [id, status]);
    return rows.length > 0;
  }

  // ── history ───────────────────────────────────────────────────────────────
  public async getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult> {
    const where: string[] = [];
    const params: any[] = [];
    if (filters?.clientId && filters.clientId !== "ALL") { params.push(filters.clientId); where.push(`client_id = $${params.length}`); }
    if (filters?.classification && filters.classification !== "ALL") { params.push(filters.classification); where.push(`classification = $${params.length}`); }
    if (filters?.search && filters.search.trim()) {
      // Escape LIKE wildcards so a search for "100%" or "_" is literal.
      const term = filters.search.trim().replace(/[\\%_]/g, m => "\\" + m);
      params.push(`%${term}%`);
      const n = params.length;
      where.push(`(url ILIKE $${n} OR domain ILIKE $${n} OR client_name ILIKE $${n} OR reason ILIKE $${n} OR matched_pattern ILIKE $${n})`);
    }
    const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const limit = Math.min(Math.max(1, Math.floor(filters?.limit ?? DEFAULT_PAGE)), MAX_PAGE);
    const offset = Math.max(0, Math.floor(filters?.offset ?? 0));

    const [count, page] = await Promise.all([
      this.q(`SELECT COUNT(*)::int AS total FROM url_events ${whereSql}`, params),
      this.q(`SELECT * FROM url_events ${whereSql} ORDER BY occurred_at DESC, id DESC LIMIT ${limit} OFFSET ${offset}`, params)
    ]);
    const total = count.rows[0]?.total ?? 0;
    return { events: page.rows.map(r => this.mapUrlEvent(r)), total, limit, offset, hasMore: offset + page.rows.length < total };
  }

  // ── aggregates (all SQL) ──────────────────────────────────────────────────
  public async getDashboardStats(clientId?: string): Promise<DashboardStatsResult> {
    const scoped = Boolean(clientId && clientId !== "ALL");
    const p = scoped ? [clientId] : [];
    const ev = scoped ? `WHERE client_id = $1` : "";
    const alActive = scoped ? `WHERE client_id = $1 AND status = 'ACTIVE'` : `WHERE status = 'ACTIVE'`;
    const alDomains = scoped ? `WHERE client_id = $1 AND domain IS NOT NULL` : `WHERE domain IS NOT NULL`;

    const [sys, buckets, active, top, recent] = await Promise.all([
      this.q(`SELECT COUNT(*)::int AS n FROM clients`),
      this.q(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE classification = 'PHISHING')::int   AS phishing,
                COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
                COUNT(*) FILTER (WHERE classification NOT IN ('PHISHING','SUSPICIOUS'))::int AS safe
         FROM url_events ${ev}`, p),
      this.q(`SELECT COUNT(*)::int AS n FROM threat_alerts ${alActive}`, p),
      this.q(`SELECT domain, COUNT(*)::int AS count FROM threat_alerts ${alDomains}
              GROUP BY domain ORDER BY count DESC, domain LIMIT 5`, p),
      this.q(`SELECT * FROM url_events ${ev} ORDER BY occurred_at DESC, id DESC LIMIT 10`, p)
    ]);
    const b = buckets.rows[0] || { total: 0, phishing: 0, suspicious: 0, safe: 0 };
    return {
      scope: scoped ? (clientId as string) : "ALL",
      totalSystems: sys.rows[0]?.n ?? 0,
      urlsMonitored: b.total,
      allowedUrls: b.safe,
      phishingIntercepted: b.phishing,
      activeAlerts: active.rows[0]?.n ?? 0,
      breakdown: { evaluated: b.total, safe: b.safe, suspicious: b.suspicious, phishing: b.phishing },
      recentEvents: recent.rows.map(r => this.mapUrlEvent(r)),
      topThreatDomains: top.rows.map(r => ({ domain: r.domain, count: r.count }))
    };
  }

  public async getReportData(clientId?: string): Promise<ReportDataResult> {
    const scoped = Boolean(clientId && clientId !== "ALL");
    const p = scoped ? [clientId] : [];
    const ev = scoped ? `WHERE client_id = $1` : "";
    const alActive = scoped ? `WHERE client_id = $1 AND status = 'ACTIVE'` : `WHERE status = 'ACTIVE'`;
    const alDomains = scoped ? `WHERE client_id = $1 AND domain IS NOT NULL` : `WHERE domain IS NOT NULL`;
    const none = Promise.resolve({ rows: [] as any[] });

    const [clients, buckets, activeAlerts, top, events, alerts, perEv, perAl] = await Promise.all([
      scoped ? this.getClientById(clientId as string).then(c => (c ? [c] : [])) : this.getClients(),
      this.q(
        `SELECT COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE classification = 'PHISHING')::int   AS phishing,
                COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
                COUNT(*) FILTER (WHERE classification NOT IN ('PHISHING','SUSPICIOUS'))::int AS safe
         FROM url_events ${ev}`, p),
      this.q(`SELECT COUNT(*)::int AS n FROM threat_alerts ${alActive}`, p),
      this.q(`SELECT domain, COUNT(*)::int AS count FROM threat_alerts ${alDomains}
              GROUP BY domain ORDER BY count DESC, domain LIMIT 10`, p),
      this.q(`SELECT * FROM url_events ${ev} ORDER BY occurred_at DESC, id DESC LIMIT 1000`, p),
      this.q(`SELECT * FROM threat_alerts ${ev} ORDER BY occurred_at DESC, id DESC LIMIT 500`, p),
      // Per-system breakdown: ONE grouped query each (the old code loaded every
      // system's full history one system at a time — an N+1).
      scoped ? none : this.q(
        `SELECT client_id,
                COUNT(*)::int AS total,
                COUNT(*) FILTER (WHERE classification = 'PHISHING')::int   AS phishing,
                COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
                COUNT(*) FILTER (WHERE classification NOT IN ('PHISHING','SUSPICIOUS'))::int AS safe
         FROM url_events GROUP BY client_id`),
      scoped ? none : this.q(`SELECT client_id, COUNT(*)::int AS n FROM threat_alerts WHERE status = 'ACTIVE' GROUP BY client_id`)
    ]);

    const b = buckets.rows[0] || { total: 0, phishing: 0, suspicious: 0, safe: 0 };
    const evBy = new Map<string, any>(perEv.rows.map((r: any) => [r.client_id, r]));
    const alBy = new Map<string, number>(perAl.rows.map((r: any) => [r.client_id, r.n]));
    const perSystem = scoped ? [] : clients.map(c => {
      const e = evBy.get(c.id) || { total: 0, safe: 0, suspicious: 0, phishing: 0 };
      return {
        clientId: c.id, clientName: c.clientName, os: c.os, browser: c.browser,
        totalScanned: e.total, safe: e.safe, suspicious: e.suspicious, phishing: e.phishing,
        activeAlerts: alBy.get(c.id) || 0
      };
    });

    return {
      scope: scoped ? (clientId as string) : "ALL",
      generatedAt: new Date().toISOString(),
      systems: clients,
      summary: { totalEvaluated: b.total, safe: b.safe, suspicious: b.suspicious, phishing: b.phishing, activeAlerts: activeAlerts.rows[0]?.n ?? 0 },
      topThreatDomains: top.rows.map((r: any) => ({ domain: r.domain, count: r.count })),
      events: events.rows.map(r => this.mapUrlEvent(r)),
      alerts: alerts.rows.map(r => this.mapThreatAlert(r)),
      perSystem
    };
  }
}
