/**
 * Central, validated environment configuration.
 *
 * Required:  DATABASE_URL            Supabase Postgres connection string
 * Optional:  PRODUCTION_API_URL      public https origin of this deployment
 *            APP_URL                 legacy alias for PRODUCTION_API_URL
 *            ENROLLMENT_KEY          if set, new extensions must present it to enroll
 *            DASHBOARD_BASIC_AUTH    "user:password" — protects dashboard API routes
 *
 * Nothing secret is hardcoded anywhere in the repository.
 */

function clean(v: string | undefined): string {
  return (v || "").trim().replace(/^["']|["']$/g, "");
}

export function getPublicOrigin(): string {
  const raw = clean(process.env.PRODUCTION_API_URL) || clean(process.env.APP_URL) || clean(process.env.URL);
  return raw.replace(/\/+$/, "");
}

export const config = {
  get databaseUrl(): string {
    return clean(process.env.DATABASE_URL);
  },
  get publicOrigin(): string {
    return getPublicOrigin();
  },
  get enrollmentKey(): string {
    return clean(process.env.ENROLLMENT_KEY);
  },
  get dashboardBasicAuth(): string {
    return clean(process.env.DASHBOARD_BASIC_AUTH);
  },
  version: "1.5.0",
  schemaVersion: "2"
};

export class ConfigError extends Error {
  status = 503;
  code = "not_configured";
}
