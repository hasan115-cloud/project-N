// Writes extension/config.js with your production API origin.
//   PRODUCTION_API_URL=https://your-site.netlify.app npm run extension:configure
import fs from "node:fs";
import path from "node:path";
import { buildConfigJs } from "../shared/extensionConfig";

const url = process.env.PRODUCTION_API_URL || process.argv[2];
if (!url) {
  console.error("Set PRODUCTION_API_URL (e.g. https://your-site.netlify.app) or pass it as an argument.");
  process.exit(1);
}
try {
  const js = buildConfigJs(url, process.env.ENROLLMENT_KEY);
  fs.writeFileSync(path.resolve(process.cwd(), "extension", "config.js"), js);
  console.log(`extension/config.js now points at ${new URL(url).origin}`);
} catch (e: any) {
  console.error("Refusing to write config:", e.message);
  process.exit(1);
}
