// Copies shared/pgcore.cjs → extension/pg-core.js so the extension runs the exact same matcher as the server.
import fs from "node:fs";
import path from "node:path";
const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const src = path.join(root, "shared", "pgcore.cjs");
const dst = path.join(root, "extension", "pg-core.js");
const out = "// GENERATED from shared/pgcore.cjs by `npm run extension:sync` — do not edit here.\n" + fs.readFileSync(src, "utf8");
if (!fs.existsSync(dst) || fs.readFileSync(dst, "utf8") !== out) { fs.writeFileSync(dst, out); console.log("extension/pg-core.js updated"); }
else console.log("extension/pg-core.js already current");
