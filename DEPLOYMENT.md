# Deployment guide

Do the steps in this order. Total time ≈ 15 minutes.

## 0. Rotate the leaked database password (do this first)
The zip you uploaded contained a live Supabase connection string (in `.env` and `.env.example`). Treat that password as compromised:
Supabase → **Project Settings → Database → Reset database password**. Use the *new* password below. Never commit `.env`
(`.gitignore` already excludes it) and never zip it.

## 1. Supabase
1. Supabase Dashboard → your project → **SQL Editor → New query**.
2. Open `supabase/schema.sql`, paste **all** of it, click **Run**. You should see "Success. No rows returned".
   * Safe on a brand-new project **and** on your existing one — it upgrades tables in place and never deletes data.
   * Re-running it later is harmless.
3. **Project Settings → Database → Connection string → Transaction pooler** (port **6543**). Copy the URI and put your new
   password in place of `[YOUR-PASSWORD]`. URL-encode special characters (`@`→`%40`, `#`→`%23`, `$`→`%24`).
   This is your `DATABASE_URL`.
4. (Optional, one time) `supabase/migrations_optional_cleanup.sql` removes the link-scan noise older versions wrote into URL History. Read it first — it previews before it deletes.

You do **not** need the anon key or the service-role key. Do not put either into Netlify or the extension.

## 2. Netlify
1. Push this project to a Git repo (make sure `.env` is not included) and **Add new site → Import from Git**.
   Build settings are read from `netlify.toml` (build `npm run build`, publish `dist`, functions `netlify/functions`).
2. **Site configuration → Environment variables** → add:

   | Variable | Value |
   |---|---|
   | `DATABASE_URL` | the pooler URI from step 1.3 — **required** |
   | `PRODUCTION_API_URL` | your site's origin, e.g. `https://phishguard.netlify.app` (no trailing slash) |
   | `DASHBOARD_BASIC_AUTH` | `admin:<long random password>` — protects all dashboard API routes |
   | `ENROLLMENT_KEY` | *(optional)* a random string; new extensions must present it to enroll |

3. **Deploys → Trigger deploy → Clear cache and deploy site.** (Variables are read at request time, but redeploy anyway so the extension ZIP/URLs are consistent.)
4. Verify: open `https://<your-site>/api/health` → must show `{"status":"ok","database":"up","schemaVersion":"2"}`.
   * `503 … DATABASE_URL is not set` → variable missing/misspelled in Netlify.
   * `503 … schema is not installed` → step 1.2 not run against *this* Supabase project.
   * `503 … Database unavailable` → wrong password/host, or project paused (free tier pauses after inactivity).
5. Open the site. With `DASHBOARD_BASIC_AUTH` set your browser will ask for the username/password.

## 3. Extension
**Recommended:** dashboard → **Install Extension → Download Extension (.ZIP)**. The ZIP is generated on the fly with your HTTPS origin
already inside `config.js`.

From source instead:
```bash
PRODUCTION_API_URL=https://<your-site> npm run extension:configure   # refuses http:// and localhost
```
Install on each computer:
1. Unzip (or use the `extension/` folder).
2. Chrome → `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the folder containing `manifest.json`.
3. Click the PhishGuard icon → the status pill must say **Online**. The computer appears in **Enrolled Systems** within seconds.
4. To update after a new release: replace the folder contents and click the reload icon on `chrome://extensions`. The system keeps its identity and history.

Notes: uninstalling the extension deletes its stored identity, so a reinstall enrolls as a **new** system (remove the old one from the dashboard).
The packaged URL can be overridden in the popup's settings, but only with an `https://` non-local address.

## 4. Manual verification in real Chrome (I could not run these; please do)
The automated tests run the extension's real code without a browser. These confirm the browser-specific parts:
1. Add a blacklist rule `example.org` on **Security Rules**; reload the dashboard → rule still listed.
2. On the computer, popup → **Update Rules** → "Synced: … 1 phishing rules".
3. Visit `https://example.org` → **red warning page** loads, a **bottom "⚠ SECURITY ALERT" toast** appears, you **hear the siren**, and an OS notification appears.
   *If there is no sound: check the popup's 🔔 toggle and that Chrome/the tab isn't muted at OS level.*
4. **URL History** shows `https://example.org` once with *Rule Triggered · Matched Rule: example.org · Rule Type: Phishing / Blacklist · Action: Blocked* (allow up to ~2 s). **Threat Alerts** shows one alert.
5. Hard-refresh the dashboard and restart Chrome → history, alert and rule are all still there.
6. Install on a second computer → two separate systems; scan on both; Overview totals equal the sum.
7. Visit `https://example.com` → no alarm; it appears in history as Allowed.
8. Disconnect the network, visit a site, reconnect → the visit appears in history within ~30 s, once.

## 5. Troubleshooting
* Popup says **Not configured** → `config.js` has no https URL; re-download the ZIP or run `extension:configure`.
* Popup says **Unreachable** → wrong URL, Netlify site down, or an ad-blocker/corporate proxy blocking the domain.
* System missing from the dashboard → open `https://<site>/api/health`; then extension → `chrome://extensions` → PhishGuard → *service worker* → Console for the error (`Registration failed: …`).
* `403 enrollment_key_required` → the extension was installed from a ZIP made before `ENROLLMENT_KEY` was set; re-download it.
* `401 id_taken` → the same system id was registered with different credentials (storage was cleared/copied between machines). Remove the system on the dashboard and reinstall.
