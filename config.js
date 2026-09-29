// PhishGuard extension configuration.
// The download from the dashboard (Install Extension → Download .ZIP) regenerates this file with
// your production HTTPS API origin. If you load the extension straight from the repository, run:
//     PRODUCTION_API_URL=https://your-site.netlify.app npm run extension:configure
// SERVER_URL must be https:// and must NOT be localhost — the extension refuses anything else.
const PHISHGUARD_DEFAULT_CONFIG = {
    SERVER_URL: "",
    ENROLLMENT_KEY: ""
};
if (typeof self !== "undefined") { self.PHISHGUARD_DEFAULT_CONFIG = PHISHGUARD_DEFAULT_CONFIG; }
if (typeof window !== "undefined") { window.PHISHGUARD_DEFAULT_CONFIG = PHISHGUARD_DEFAULT_CONFIG; }
