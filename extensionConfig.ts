/**
 * Single place that renders extension/config.js. Used by the server-side
 * packager and by scripts/configure-extension.mjs (build-time), so both
 * produce identical output and apply identical safety rules.
 */
export function assertProductionOrigin(raw: string): string {
  let u: URL;
  try { u = new URL(raw); } catch { throw new Error(`Invalid API URL: "${raw}"`); }
  if (u.protocol !== "https:") throw new Error(`The extension must use an https:// API URL (got "${u.protocol}//${u.host}")`);
  if (/^(localhost|127\.|10\.|192\.168\.|0\.0\.0\.0|\[::1\])/.test(u.hostname) || /\.local$/.test(u.hostname)) {
    throw new Error(`The extension may not point at a local address (${u.hostname})`);
  }
  return u.origin;
}

export function buildConfigJs(serverOrigin: string, enrollmentKey?: string): string {
  const origin = assertProductionOrigin(serverOrigin);
  return `// PhishGuard extension configuration — GENERATED, do not hand-edit.
// Production API origin (HTTPS only). Rebuild with: npm run extension:configure
const PHISHGUARD_DEFAULT_CONFIG = {
    SERVER_URL: ${JSON.stringify(origin)},
    ENROLLMENT_KEY: ${JSON.stringify(enrollmentKey || "")}
};
if (typeof self !== "undefined") { self.PHISHGUARD_DEFAULT_CONFIG = PHISHGUARD_DEFAULT_CONFIG; }
if (typeof window !== "undefined") { window.PHISHGUARD_DEFAULT_CONFIG = PHISHGUARD_DEFAULT_CONFIG; }
`;
}
