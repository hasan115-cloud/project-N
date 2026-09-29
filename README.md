# PhishGuard

Chrome extension + management dashboard. **Supabase PostgreSQL is the only data store**: enrolled systems,
security rules, URL history, threat alerts and report data all live in the database. Nothing important is
kept in browser storage, JSON files or server memory.

```
Chrome extension ──HTTPS──► Netlify Function (Express API) ──► Supabase Postgres ◄── Dashboard (React)
   (per-system id + secret)        server/app.ts                 supabase/schema.sql      src/
```

| Path | What |
|---|---|
| `supabase/schema.sql` | **The** database schema. Paste into Supabase → SQL Editor. Idempotent. |
| `shared/pgcore.cjs` | URL normalization + rule matching + precedence. Used by server **and** extension. |
| `server/` | Express API (`app.ts`), Postgres layer (`pgdb.ts`), classifier (`detector.ts`) |
| `netlify/functions/api.ts` | Netlify entry point wrapping the Express app |
| `src/` | Dashboard (React + Tailwind) — unchanged look and features |
| `extension/` | Chrome extension (Manifest V3) |
| `scripts/` | Unit, API and extension end-to-end tests; build helpers |
| `DEPLOYMENT.md` | Step-by-step setup (Supabase, Netlify, extension) |
| `AUDIT.md` | Findings, root causes and the PASS/FIXED/NEEDS-CONFIGURATION report |

## Rule precedence (deterministic)
Only enabled rules count → the **most specific** matching rule wins (URL-path rule > deeper domain > shallower
domain) → on a tie **whitelist beats blacklist** → then oldest rule. Matching is host-boundary aware:
`paypal.com` matches `paypal.com` and `*.paypal.com`, never `evil.xyz/paypal.com`.

## Environment variables
See `.env.example`. Required: `DATABASE_URL`. Recommended: `PRODUCTION_API_URL`, `DASHBOARD_BASIC_AUTH`.
Optional: `ENROLLMENT_KEY`. No other variables are read. The Supabase **service-role key is not used anywhere**.

## Commands
```bash
npm install
npm run dev                # API + dashboard on http://localhost:3000 (needs DATABASE_URL)
npm run build              # dashboard + server bundle (Netlify runs this)
npm test                   # 15 unit tests for the matcher
npm run test:e2e           # API integration tests   (needs a running server + scratch database)
npm run test:extension     # runs the real extension code against the real server + database
npm run extension:configure   # write extension/config.js  (PRODUCTION_API_URL=https://... )
```
> `test:e2e` / `test:extension` write data. Point them at a **scratch** database, never production.
