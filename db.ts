import { IDatabase, HttpError } from "./dbTypes";
import { PostgresDatabase } from "./pgdb";
import { config } from "./config";

/**
 * The one and only storage backend is Supabase PostgreSQL.
 *
 * If DATABASE_URL is missing we do NOT fall back to files, /tmp or memory (the
 * old behaviour — on Netlify that gave every function instance its own private
 * store, which is exactly how rules and history "disappeared"). Instead every
 * call fails with a clear HTTP 503 so the misconfiguration is impossible to miss.
 */
let instance: IDatabase | null = null;

function create(): IDatabase {
  const url = config.databaseUrl;
  if (!url) {
    const fail = () => {
      throw new HttpError(
        503,
        "DATABASE_URL is not set. Add your Supabase connection string to the server environment (Netlify → Site configuration → Environment variables) and redeploy.",
        "not_configured"
      );
    };
    return new Proxy({} as IDatabase, { get: () => async () => fail() });
  }
  return new PostgresDatabase(url);
}

export const db: IDatabase = new Proxy({} as IDatabase, {
  get(_t, prop) {
    if (!instance) instance = create();
    const v = (instance as any)[prop];
    return typeof v === "function" ? v.bind(instance) : v;
  }
});
