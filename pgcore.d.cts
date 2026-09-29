export interface NormalizedUrl {
  ok: true;
  href: string;
  host: string;
  path: string;
  normalized: string;
}
export type NormalizeResult = NormalizedUrl | { ok: false; error: string };
export type PatternResult =
  | { ok: true; pattern: string; kind: "domain" | "url" }
  | { ok: false; error: string };
export interface RuleLike {
  id: string;
  pattern: string;
  enabled?: boolean;
  createdAt?: string;
  [k: string]: any;
}
export interface RuleMatch {
  type: "WHITELIST" | "PHISHING";
  action: "ALLOWED" | "BLOCKED";
  ruleId: string;
  pattern: string;
  rule: any;
}
declare const core: {
  MAX_URL_LENGTH: number;
  SAFE_APEX: Set<string>;
  apexDomain(host: string): string;
  isSafeApex(host: string): boolean;
  normalizeUrl(raw: unknown): NormalizeResult;
  normalizePattern(raw: unknown): PatternResult;
  patternMatches(norm: NormalizedUrl, pattern: string): boolean;
  evaluateRules(url: string | NormalizedUrl, rules: { whitelist?: RuleLike[]; phishing?: RuleLike[] }): RuleMatch | null;
  isInternalHost(host: string, extraHosts?: string[]): boolean;
};
export default core;
