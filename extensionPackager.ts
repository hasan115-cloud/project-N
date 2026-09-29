import fs from "fs";
import path from "path";
import JSZip from "jszip";
import { buildConfigJs } from "../shared/extensionConfig";

// Netlify Functions run from LAMBDA_TASK_ROOT; locally we run from the repo root.
const ROOTS = [process.env.LAMBDA_TASK_ROOT, process.cwd()].filter(Boolean) as string[];
const firstExisting = (...rel: string[]) =>
  ROOTS.map(r => path.resolve(r, ...rel)).find(p => fs.existsSync(p)) || path.resolve(ROOTS[ROOTS.length - 1], ...rel);
const EXTENSION_DIR = firstExisting("extension");
const SHARED_CORE = firstExisting("shared", "pgcore.cjs");

const BINARY = /\.(png|jpg|jpeg|ico|gif|webp)$/i;

/**
 * Builds the installable extension ZIP with the production API origin baked
 * into config.js. The origin must be https:// (localhost is refused) — the
 * extension itself re-validates this at runtime.
 */
export async function generateExtensionZip(serverOrigin: string, enrollmentKey?: string): Promise<Buffer> {
  if (!fs.existsSync(EXTENSION_DIR)) throw new Error("Extension directory not found at " + EXTENSION_DIR);
  const configJs = buildConfigJs(serverOrigin, enrollmentKey); // throws on non-https / localhost

  const zip = new JSZip();
  for (const filename of fs.readdirSync(EXTENSION_DIR)) {
    const filePath = path.join(EXTENSION_DIR, filename);
    if (!fs.statSync(filePath).isFile()) continue;
    if (filename === "config.js" || filename === "pg-core.js") continue; // generated below
    zip.file(filename, BINARY.test(filename) ? fs.readFileSync(filePath) : fs.readFileSync(filePath, "utf-8"));
  }
  zip.file("config.js", configJs);

  // Always ship the CURRENT shared core so the extension and server match exactly.
  const corePath = fs.existsSync(SHARED_CORE) ? SHARED_CORE : path.join(EXTENSION_DIR, "pg-core.js");
  zip.file("pg-core.js", fs.readFileSync(corePath, "utf-8"));

  return zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 9 } });
}
