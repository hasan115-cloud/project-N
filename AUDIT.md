# PhishGuard — A-to-Z audit (v1.5)

Legend: **PASS** = verified by an automated test that ran the real code against a real PostgreSQL 16 ·
**FIXED** = defect found in the uploaded code and corrected (with the test that proves it) ·
**NEEDS CONFIGURATION** = correct in code, requires a step only you can do ·
**NOT VERIFIED HERE** = I could not exercise it in this environment (no Chrome, no Netlify, no Supabase access).

## 1. Root causes of the problems you reported

| Symptom | Actual root cause in the uploaded code | Fix |
|---|---|---|
| Rules / history disappear after refresh, "data appears then vanishes" | `server/db.ts` **silently fell back to a JSON file in `/tmp`** whenever `DATABASE_URL` was not visible to the function. On Netlify every function instance has its own private `/tmp`, wiped on cold start → a different instance answered each request. (I can't see your Netlify environment, so I can't prove this is what happened to *you*; it is the only mechanism in the code that produces exactly these symptoms.) | File store **deleted**. No `DATABASE_URL` / no schema / DB down → HTTP 503 with an explicit message. Tested: unset var, empty DB, unreachable DB, restart. |
| URL History shows URLs nobody visited, huge & inconsistent | The content scripts scan **every link on every page** through `/bulk-scan`, and each scan was **written to URL History**. | `/bulk-scan` classifies only. History = navigations, redirects, explicit scans, blocked clicks. Dashboard/API/Supabase hosts filtered. |
| History "flickers" / results revert | `UrlHistoryView` polled with a **stale closure**: the interval was created before the user typed, so each poll re-queried with the *old* search term and overwrote the filtered list. Dashboard also rendered **zeros before the first response** and only `console.error`'d failures. | Filters committed to a ref read by every fetch; polls **merge** (never shrink); `null`=not-loaded (not zero); failures keep last-good data + visible banner; superseded requests aborted. |
| Blocked URL produced up to 3 alerts | Extension `scanUrl` alert + `redirectToWarning` alert + server-side alert from `/url-events`. | One path: server writes history+alert in one transaction, deduped on `(client_id,event_id)`. Tested: exactly 1. |
| Whitelist entry could whitelist attackers | Substring match: rule `paypal.com` matched `evil.xyz/paypal.com`. Extension checked phishing first, server whitelist first → they disagreed. | One shared matcher, host-boundary aware, documented precedence. Unit + API + extension tests. |
| Extension pointed at `localhost:3000` | `config.js` default persisted into storage on first run, so later config never applied. | Default never persisted; only validated `https://` non-local URLs accepted. |
| Events lost under load | Queue read-modify-write on `chrome.storage` was unsynchronized. | Web Lock around queue mutation. Tested: 30 overlapping navigations → 30 rows. |
| "Alarm" was a silent notification | No audio path without a user click. | Offscreen document plays a siren on a real block only. |
| Live DB password in the zip | `.env` and `.env.example` | Removed. **Rotate the password.** |

## 2. Results

| Area | Status | Evidence / notes |
|---|---|---|
| Extension | **FIXED** · NEEDS CONFIGURATION · NOT VERIFIED HERE (real Chrome) | 33 checks run the real `background.js` + `pg-core.js`: identity stable across 5 cold starts; no re-register storm; instant local block; queue survives restart/offline/lost response; rules survive offline restart; refuses http/localhost; legacy installs keep their id. Configuration: download the ZIP from the deployed dashboard. |
| Server | **PASS** | 37 API checks + serverless-handler invocation with Lambda events (`/api/…`, `/.netlify/functions/api/…`, ZIP download as base64) + `npm start` production build serving the dashboard + curl checks of `DASHBOARD_BASIC_AUTH` (401/200, `WWW-Authenticate`, ZIP protected) and `ENROLLMENT_KEY` (403 without/with wrong key, 200 with it, already-enrolled systems unaffected). |
| Supabase | **FIXED** · NEEDS CONFIGURATION | `schema.sql` tested on a fresh DB, on the old runtime-created schema with data (kept, orphans repaired), and re-run twice. **Not run against your Supabase project** — you must run it (DEPLOYMENT §1). |
| Rules | **PASS** | Add / edit / enable-disable / delete, duplicate 409, invalid 400, version bump, extension pulls only on change, disabled rules stop blocking. |
| URL History | **FIXED** | Exact URL recorded once with `matched_pattern`, `rule_type`, action; replay & lost-response don't duplicate; pagination stable; system isolation. UI behaviour verified by type-check + build only — **no visual/browser test**. |
| Alerts | **FIXED** · NOT VERIFIED HERE (audio, toast rendering) | One alert per detection, persisted, carries the rule. The extension code path that plays the alarm/creates the notification/redirects is exercised; that Chrome actually *sounds* the siren and *draws* the toast needs the manual check in DEPLOYMENT §4. |
| Reports | **FIXED** | Per-system report was an N+1 loading every system's full history; now 2 grouped SQL queries. Totals verified equal to sum of rows. PDF/print export code unchanged, not re-tested. |
| Multi-system | **PASS** | Two extensions, separate identities/histories, same `eventId` on two systems doesn't collide, totals = Σ systems, deleting one leaves the other untouched, deleted system transparently re-enrols. |
| API connectivity | **FIXED** · NEEDS CONFIGURATION | HTTPS-only, timeouts (8 s scan / 10 s API / 15 s batch), backoff (2 s → 5 min), 401 → re-register. Needs `DATABASE_URL` + `PRODUCTION_API_URL` on Netlify. **Not tested on live Netlify.** |
| Persistence | **PASS** | Server restart: 255 events / rules identical before and after. Everything in Postgres. |
| Security | **FIXED** with caveats | Per-system secret (SHA-256 stored, constant-time compare), client id taken from credentials not body, id-hijack refused, input validation everywhere, RLS enabled with no policies, CORS restricted, no service-role key anywhere, secrets never logged. **Caveats below.** |
| Performance | **PASS** | 300k rows / 3 systems, wall-clock per query including ~35 ms of psql connection overhead: history page 1 ≈ 40 ms, deep page (offset 100k) ≈ 64 ms, URL search (trigram index) ≈ 85 ms, overview aggregate ≈ 99 ms. Everything ≤ 100 ms. No polling when tab hidden; rules re-downloaded only when version changes; heartbeat ≈ 1 tiny request / 30 s. |

## 3. Caveats & decisions you should know about

1. **Dashboard has no login** (your earlier decision). Without `DASHBOARD_BASIC_AUTH`, anyone who knows the URL can edit rules, delete systems and read history. Set it. The browser's Basic-auth prompt for `fetch()` calls is standard behaviour but **I did not test it in a browser**.
2. **Behaviour change:** links merely *shown* on a page no longer appear in URL History (they still get badges). URL History defaults to 200 rows/page with "Load more" (was: everything in one response).
3. **Legacy rules:** matching is now domain/URL-path aware. A stored rule that is a bare *keyword* (e.g. `login-secure`, no dot) can no longer match anything. Check yours: `select pattern from phishing_rules where pattern !~ '\.'; select pattern from whitelist_rules where pattern !~ '\.';` and re-enter them as domains.
4. **Blocking is fast, not synchronous.** MV3 cannot pause a request while an extension decides. Rule matches redirect within milliseconds without a network call; heuristic verdicts need a server round-trip (typically 100–500 ms), so the page may begin loading first.
5. **"Proceed anyway"** visits are not logged. Uninstalling the extension erases its identity; reinstall = new system.
6. **TLS:** connections to Postgres are encrypted but the server certificate chain is not pinned (`rejectUnauthorized:false`, as before) because Node's CA bundle often lacks Supabase's issuer. Pin Supabase's CA if you need that.
7. `ENROLLMENT_KEY`, if used, is embedded in the downloadable ZIP — treat the ZIP as private.
8. Old `heartbeats` table (if present in your DB) is now unused; harmless, not dropped.
9. Framework: the project is Vite + Express (not Next.js App Router). You asked me to keep the architecture; I did.
