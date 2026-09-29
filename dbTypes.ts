import {
  DecisionSource,
  EnrolledClient,
  PhishingRule,
  RuleSet,
  RuleType,
  ThreatAlert,
  UrlClassification,
  UrlEvent,
  UrlVerdict,
  WhitelistRule
} from "./types";

export class HttpError extends Error {
  constructor(public status: number, message: string, public code = "error") {
    super(message);
  }
}

export interface UrlEventFilters {
  clientId?: string;
  classification?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export interface UrlEventsResult {
  events: UrlEvent[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
}

export interface DashboardStatsResult {
  scope: string;
  totalSystems: number;
  urlsMonitored: number;
  allowedUrls: number;
  phishingIntercepted: number;
  activeAlerts: number;
  breakdown: { evaluated: number; safe: number; suspicious: number; phishing: number };
  recentEvents: UrlEvent[];
  topThreatDomains: { domain: string; count: number }[];
}

export interface ReportDataResult {
  scope: string;
  generatedAt: string;
  systems: EnrolledClient[];
  summary: { totalEvaluated: number; safe: number; suspicious: number; phishing: number; activeAlerts: number };
  topThreatDomains: { domain: string; count: number }[];
  events: UrlEvent[];
  alerts: ThreatAlert[];
  perSystem: {
    clientId: string;
    clientName: string;
    os: string;
    browser: string;
    totalScanned: number;
    safe: number;
    suspicious: number;
    phishing: number;
    activeAlerts: number;
  }[];
}

export interface AuthedClient {
  id: string;
  clientName: string;
}

export interface DetectionInput {
  eventId?: string;
  client: AuthedClient;
  url: string;
  normalizedUrl: string;
  domain: string;
  classification: UrlClassification;
  verdict: UrlVerdict;
  score: number;
  reason: string;
  source: string;
  ruleType: RuleType | null;
  matchedRuleId: string | null;
  matchedPattern: string | null;
  decisionSource: DecisionSource;
  observedAt?: string;
  /** When set, a Threat Alert is written in the SAME transaction (deduped per eventId). */
  alertReasons?: string[];
}

export interface RuleInput {
  pattern: string;               // already validated/normalized by the caller
  description?: string;          // whitelist
  reason?: string;               // phishing
  severity?: "HIGH" | "CRITICAL";
  enabled?: boolean;
}

export type AnyRule = WhitelistRule | PhishingRule;

export interface IDatabase {
  ping(): Promise<{ schemaVersion: string }>;

  // Rules
  getRules(): Promise<RuleSet>;
  /** Enabled rules, cached per instance but re-validated against rules_meta.version on every call. */
  getActiveRules(): Promise<RuleSet>;
  addRule(type: RuleType, input: RuleInput, addedBy?: string): Promise<AnyRule>;
  updateRule(type: RuleType, id: string, patch: Partial<RuleInput>): Promise<AnyRule | null>;
  deleteRule(type: RuleType, id: string): Promise<boolean>;

  // Systems
  /** Returns null when the id is already owned by a different secret. */
  registerClient(
    p: { clientId: string; clientName?: string; os?: string; browser?: string; platform?: string; extensionVersion?: string; ip?: string },
    secretHash: string
  ): Promise<EnrolledClient | null>;
  authenticateClient(clientId: string, secretHash: string): Promise<AuthedClient | null>;
  clientHasCredentials(clientId: string): Promise<boolean>;
  heartbeatClient(clientId: string, stats: Record<string, number> | undefined, patch: { clientName?: string; ip?: string; extensionVersion?: string }): Promise<void>;
  getClients(): Promise<EnrolledClient[]>;
  clientExists(id: string): Promise<boolean>;
  getClientById(id: string): Promise<EnrolledClient | null>;
  deleteClient(id: string): Promise<boolean>;

  // Detections
  recordDetections(inputs: DetectionInput[]): Promise<{ wasNew: boolean }[]>;
  recordAlert(a: {
    eventId: string; client: AuthedClient; url: string; domain: string; score: number;
    reasons: string[]; source: string;
  }): Promise<{ wasNew: boolean; alert: ThreatAlert }>;
  getThreatAlerts(clientId?: string, limit?: number): Promise<ThreatAlert[]>;
  updateThreatAlertStatus(id: string, status: "ACKNOWLEDGED" | "RESOLVED" | "ACTIVE"): Promise<boolean>;
  getUrlEvents(filters?: UrlEventFilters): Promise<UrlEventsResult>;

  // Aggregates
  getDashboardStats(clientId?: string): Promise<DashboardStatsResult>;
  getReportData(clientId?: string): Promise<ReportDataResult>;
}
