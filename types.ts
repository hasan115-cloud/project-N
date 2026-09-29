export type SystemStatus = "ENROLLED";

// A system heartbeats roughly every 30s (chrome.alarms "pg_heartbeat").
// Three missed heartbeats — 90s of silence — is displayed as OFFLINE. This is
// derived at READ time only: it never removes a system, never affects Total
// Enrolled Systems and is never persisted. Only an explicit
// DELETE /api/clients/:id removes a system.
export const ONLINE_THRESHOLD_MS = 90_000;

export type UrlClassification = "SAFE" | "SUSPICIOUS" | "PHISHING";
export type UrlVerdict = "ALLOWED" | "WARNING" | "BLOCKED";
export type ThreatStatus = "ACTIVE" | "ACKNOWLEDGED" | "RESOLVED";
export type RuleType = "WHITELIST" | "PHISHING";
export type DecisionSource = "rule" | "safe-list" | "trusted" | "heuristic";

export interface EnrolledClient {
  id: string;
  clientName: string;
  firstSeen: string;
  lastSeen: string;
  status: SystemStatus;
  // "OFFLINE" == no recent heartbeat, NOT "uninstalled". Display-only.
  connectionStatus: "ONLINE" | "OFFLINE";
  extensionVersion: string;
  browser: string;
  os: string;
  platform: string;
  ip: string;
  // Always derived from url_events (never a stored counter that can drift).
  telemetryStats: {
    totalScanned: number;
    phishingBlocked: number;
    suspiciousDetected: number;
    safeEvaluated: number;
  };
}

export interface UrlEvent {
  id: string;
  eventId?: string;
  timestamp: string;
  clientId: string;
  clientName: string;
  url: string;
  normalizedUrl?: string;
  domain: string;
  classification: UrlClassification;
  verdict: UrlVerdict;            // the action taken: ALLOWED | WARNING | BLOCKED
  score: number;
  reason: string;
  source: string;
  // True ONLY when an administrator whitelist/blacklist rule actually matched.
  ruleTriggered?: boolean;
  ruleType?: RuleType | null;
  matchedRuleId?: string | null;
  matchedPattern?: string | null;
  decisionSource?: DecisionSource | null;
}

export interface ThreatAlert {
  id: string;
  eventId?: string;
  timestamp: string;
  clientId: string;
  clientName: string;
  url: string;
  domain: string;
  score: number;
  reasons: string[];
  source: string;
  status: ThreatStatus;
  matchedRuleId?: string | null;
  matchedPattern?: string | null;
  ruleType?: RuleType | null;
  action?: string;
}

export interface WhitelistRule {
  id: string;
  pattern: string;
  description: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  addedBy: string;
}

export interface PhishingRule {
  id: string;
  pattern: string;
  severity: "HIGH" | "CRITICAL";
  reason: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  addedBy: string;
}

export interface RuleSet {
  whitelist: WhitelistRule[];
  phishing: PhishingRule[];
  version: number;
}
