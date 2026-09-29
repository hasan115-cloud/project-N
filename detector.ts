import core, { NormalizedUrl } from "../shared/pgcore.cjs";
import { DecisionSource, RuleSet, RuleType, UrlClassification, UrlVerdict } from "./types";

/**
 * URL classification. Order of evaluation (deterministic):
 *   1. Administrator rules (whitelist + phishing) via the shared matcher —
 *      precedence documented in shared/pgcore.cjs.
 *   2. Known-safe apex domains.
 *   3. Heuristic scoring.
 * Pure function: rules are passed in, no I/O, so it is trivially testable and
 * uses the exact same matching code as the extension.
 */

const SUSPICIOUS_TLDS = new Set([
  "xyz", "top", "work", "click", "loan", "zip", "gq", "tk", "cf", "ml", "ga", "buzz", "rest", "surf"
]);

const SENSITIVE_KEYWORDS = [
  "login", "signin", "verify", "secure", "account", "banking", "update", "password",
  "credential", "wallet", "support", "auth", "confirm", "security", "recover"
];

const TARGET_BRANDS = [
  "paypal", "apple", "microsoft", "google", "netflix", "chase", "bankofamerica",
  "wellsfargo", "amazon", "facebook", "coinbase", "binance", "metamask", "steam"
];

export interface ScanResult {
  verdict: UrlClassification;
  action: UrlVerdict;
  score: number;
  domain: string;
  reasons: string[];
  ruleType: RuleType | null;
  matchedRuleId: string | null;
  matchedPattern: string | null;
  decisionSource: DecisionSource;
  whitelisted: boolean;
  policyMatched: boolean;
}

export function classifyUrl(norm: NormalizedUrl, rules: RuleSet): ScanResult {
  const hostname = norm.host;
  const base = {
    domain: hostname,
    ruleType: null as RuleType | null,
    matchedRuleId: null as string | null,
    matchedPattern: null as string | null,
    whitelisted: false,
    policyMatched: false
  };

  // 1. Administrator rules
  const m = core.evaluateRules(norm, rules);
  if (m) {
    if (m.type === "WHITELIST") {
      return {
        ...base, verdict: "SAFE", action: "ALLOWED", score: 0,
        reasons: [`Allowed by Administrator Whitelist Rule: "${m.pattern}"`],
        ruleType: "WHITELIST", matchedRuleId: m.ruleId, matchedPattern: m.pattern,
        decisionSource: "rule", whitelisted: true
      };
    }
    return {
      ...base, verdict: "PHISHING", action: "BLOCKED", score: 0.99,
      reasons: [`Blocked by Administrator Phishing Rule: "${m.pattern}" — ${m.rule?.reason || "Threat rule"}`],
      ruleType: "PHISHING", matchedRuleId: m.ruleId, matchedPattern: m.pattern,
      decisionSource: "rule", policyMatched: true
    };
  }

  // 2. Known-safe apex
  if (core.isSafeApex(hostname)) {
    return {
      ...base, verdict: "SAFE", action: "ALLOWED", score: 0.02,
      reasons: ["Recognized verified major enterprise domain"], decisionSource: "safe-list"
    };
  }

  // 3. Heuristics
  const reasons: string[] = [];
  let riskScore = 0.05;
  const parts = hostname.split(".");
  const fullUrlLower = norm.href.toLowerCase();

  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    riskScore += 0.65;
    reasons.push("Direct IP address host without domain registration");
  }
  if (hostname.includes("xn--")) {
    riskScore += 0.55;
    reasons.push("Internationalized domain name (Punycode) detected (potential spoofing)");
  }
  if (parts.length > 4) {
    riskScore += 0.35;
    reasons.push(`Unusually deep subdomain nesting (${parts.length} labels)`);
  }
  const tld = parts[parts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    riskScore += 0.3;
    reasons.push(`High-abuse top-level domain (.${tld})`);
  }
  let brandSpoofDetected = false;
  for (const brand of TARGET_BRANDS) {
    if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`) && !hostname.endsWith(`${brand}.net`)) {
      riskScore += 0.55;
      brandSpoofDetected = true;
      reasons.push(`Brand targeting detected: "${brand}" in non-official domain`);
      break;
    }
  }
  let keywordCount = 0;
  for (const kw of SENSITIVE_KEYWORDS) if (fullUrlLower.includes(kw)) keywordCount++;
  if (keywordCount >= 2) {
    riskScore += 0.35;
    reasons.push(`Multiple deceptive security/credential terms detected (${keywordCount} keywords)`);
  } else if (keywordCount === 1 && brandSpoofDetected) {
    riskScore += 0.25;
    reasons.push("Combination of target brand name and authentication keyword");
  }
  if (norm.href.length > 90 && keywordCount > 0) {
    riskScore += 0.2;
    reasons.push("Abnormally long disguised URL string");
  }

  const finalScore = Math.min(0.99, Math.max(0.01, riskScore));
  let verdict: UrlClassification = "SAFE";
  let action: UrlVerdict = "ALLOWED";
  if (finalScore >= 0.65) { verdict = "PHISHING"; action = "BLOCKED"; }
  else if (finalScore >= 0.4) { verdict = "SUSPICIOUS"; action = "WARNING"; }
  else if (reasons.length === 0) reasons.push("Standard clean domain heuristics passed");

  return {
    ...base, verdict, action, score: parseFloat(finalScore.toFixed(2)), reasons, decisionSource: "heuristic"
  };
}
