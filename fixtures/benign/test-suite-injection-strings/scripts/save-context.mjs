// Save a working set of editor tab titles into .context/session.json.
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const DANGEROUS = /[`$;&|<>(){}\\]/g;

export function sanitiseTitle(raw) {
  return String(raw).replace(DANGEROUS, "").trim().slice(0, 200);
}

export function save(dir, title, tabs) {
  const target = join(dir, ".context");
  mkdirSync(target, { recursive: true });
  const payload = {
    title: sanitiseTitle(title),
    tabs: tabs.map(sanitiseTitle),
    savedAt: new Date().toISOString(),
  };
  writeFileSync(join(target, "session.json"), JSON.stringify(payload, null, 2));
  return payload;
}

if (process.argv[1] && process.argv[1].endsWith("save-context.mjs")) {
  save(process.cwd(), process.argv[2] || "session", process.argv.slice(3));
}
