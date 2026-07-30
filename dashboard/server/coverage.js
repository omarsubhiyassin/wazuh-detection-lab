// ATT&CK coverage: which techniques we have written our OWN detections for.
//
// WHY THIS EXISTS:
//   The matrix colours techniques by alert count, so a technique we have no
//   rule for and a technique with a solid rule that simply never fired look
//   identical — both empty. Those are opposite situations. One is a blind spot;
//   the other is a quiet win. Reading alert volume as coverage is the classic
//   way to convince yourself a SOC is covered when it is not.
//
//   Cross-referencing the ruleset against observed alerts separates them:
//     covered + alerts   -> a detection that demonstrably works
//     covered + silence  -> covered, nothing happened (NOT a gap)
//     no rule + alerts   -> caught only by the vendor ruleset; no detection of our own
//     no rule + silence  -> a genuine blind spot
//
// PARSING:
//   Deliberately a regex over a file we author ourselves, not an XML dependency.
//   local_rules.xml is a multi-root Wazuh fragment (several <group>), so most
//   parsers need it wrapped anyway, and CI already checks it is well-formed with
//   unique rule IDs. Comments are stripped first so a commented-out rule never
//   counts as coverage. If the file cannot be read, coverage is reported as
//   unknown rather than as "no coverage" — silently claiming a gap that does not
//   exist would be worse than saying nothing.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FILE = process.env.DASH_RULES_FILE ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..",
    "detections", "rules", "local_rules.xml");

/**
 * Extract technique -> covering rules from a Wazuh rules fragment.
 * Pure, so it can be tested against fixtures without touching the filesystem.
 */
export function parse(xml) {
  const clean = String(xml).replace(/<!--[\s\S]*?-->/g, "");
  const byTechnique = {};
  const rules = [];

  const ruleRe = /<rule\s+([^>]*?)>([\s\S]*?)<\/rule>/g;
  for (const m of clean.matchAll(ruleRe)) {
    const attrs = m[1];
    const body = m[2];
    const id = /\bid\s*=\s*"([^"]+)"/.exec(attrs)?.[1];
    if (!id) continue;
    const level = Number(/\blevel\s*=\s*"([^"]+)"/.exec(attrs)?.[1] ?? 0);
    const description = /<description>([\s\S]*?)<\/description>/.exec(body)?.[1]?.trim() ?? "";
    rules.push({ id, level });

    // Only the <mitre> block counts. A technique id mentioned in a description
    // is documentation, not a mapping.
    const mitre = /<mitre>([\s\S]*?)<\/mitre>/.exec(body)?.[1];
    if (!mitre) continue;
    for (const t of mitre.matchAll(/<id>\s*([^<\s]+)\s*<\/id>/g)) {
      const tech = t[1];
      (byTechnique[tech] ??= []).push({ id, level, description });
    }
  }

  return {
    byTechnique,
    ruleCount: rules.length,
    // Base rules are level 0 plumbing, not detections — worth separating so
    // "24 rules" is not quoted as "24 detections".
    detectionCount: rules.filter((r) => r.level > 0).length,
    mappedRuleCount: new Set(
      Object.values(byTechnique).flat().map((r) => r.id)).size,
  };
}

// Cached by mtime so editing the ruleset shows up without a BFF restart.
let cache = null;

/** Current coverage, or `{ error }` when the ruleset cannot be read. */
export function read() {
  let stat;
  try {
    stat = fs.statSync(FILE);
  } catch {
    return { error: `rules file not readable: ${FILE}`, source: FILE, byTechnique: {} };
  }
  const key = `${stat.mtimeMs}:${stat.size}`;
  if (cache?.key === key) return cache.value;

  try {
    const parsed = parse(fs.readFileSync(FILE, "utf8"));
    const value = { ...parsed, source: FILE, readAt: new Date().toISOString() };
    cache = { key, value };
    return value;
  } catch (e) {
    return { error: String(e), source: FILE, byTechnique: {} };
  }
}
