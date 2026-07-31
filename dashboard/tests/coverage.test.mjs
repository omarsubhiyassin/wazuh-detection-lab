// Tests for ATT&CK coverage parsing.
//
// The failure mode that matters is not a crash — it is reporting confident
// coverage that is wrong in either direction. Claiming a rule exists when it is
// commented out hides a blind spot; claiming no coverage when the ruleset just
// failed to load invents one. Both are tested.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const { parse } = await import("../server/coverage.js");

const RULES = `
<group name="detection_lab,sysmon,">
  <rule id="100100" level="0">
    <if_group>sysmon_event1</if_group>
    <description>Sysmon: process creation base.</description>
  </rule>
  <rule id="100101" level="12">
    <if_sid>100100,100105</if_sid>
    <description>Encoded PowerShell command line executed.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
  <rule id="100430" level="13">
    <if_sid>100101</if_sid>
    <description>Encoded PowerShell then tool transfer.</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1105</id>
    </mitre>
  </rule>
</group>
`;

test("rules are mapped to every technique they declare", () => {
  const c = parse(RULES);
  assert.deepEqual(Object.keys(c.byTechnique).sort(), ["T1059.001", "T1105"]);
  assert.deepEqual(c.byTechnique["T1059.001"].map((r) => r.id), ["100101", "100430"]);
  assert.deepEqual(c.byTechnique.T1105.map((r) => r.id), ["100430"]);
});

test("rule level and description are carried through for the tooltip", () => {
  const r = parse(RULES).byTechnique["T1059.001"][0];
  assert.equal(r.level, 12);
  assert.equal(r.description, "Encoded PowerShell command line executed.");
});

test("base rules count as rules but not as detections", () => {
  const c = parse(RULES);
  assert.equal(c.ruleCount, 3);
  assert.equal(c.detectionCount, 2, "level 0 plumbing is not a detection");
  assert.equal(c.mappedRuleCount, 2);
});

test("a commented-out rule is not coverage", () => {
  // The dangerous direction: believing a disabled detection protects you.
  const c = parse(`
    <!--
    <rule id="100600" level="12">
      <description>disabled</description>
      <mitre><id>T1070.001</id></mitre>
    </rule>
    -->
    <rule id="100601" level="12">
      <description>live</description>
      <mitre><id>T1105</id></mitre>
    </rule>
  `);
  assert.equal(c.byTechnique["T1070.001"], undefined);
  assert.deepEqual(Object.keys(c.byTechnique), ["T1105"]);
  assert.equal(c.ruleCount, 1);
});

test("recalibrating a vendor rule is not coverage we can claim", () => {
  // An overwrite carries the vendor's own <mitre> block. Counting it would
  // report a severity change as a detection we authored.
  const c = parse(`
    <rule id="92213" level="10" overwrite="yes">
      <if_group>sysmon_event_11</if_group>
      <description>Executable file dropped in folder commonly used by malware</description>
      <mitre><id>T1105</id></mitre>
    </rule>
    <rule id="100310" level="12">
      <description>ours</description>
      <mitre><id>T1105</id></mitre>
    </rule>
  `);
  assert.deepEqual(c.byTechnique.T1105.map((r) => r.id), ["100310"]);
  assert.equal(c.ruleCount, 1);
  assert.equal(c.detectionCount, 1);
});

test("a technique named only in prose is not a mapping", () => {
  const c = parse(`
    <rule id="100999" level="10">
      <description>Looks like T1003.001 credential dumping.</description>
    </rule>
  `);
  assert.deepEqual(c.byTechnique, {}, "only the <mitre> block counts");
});

test("rules with no mitre block are counted but map nowhere", () => {
  const c = parse(`<rule id="100050" level="5"><description>x</description></rule>`);
  assert.equal(c.ruleCount, 1);
  assert.equal(c.detectionCount, 1);
  assert.equal(c.mappedRuleCount, 0);
  assert.deepEqual(c.byTechnique, {});
});

test("an empty or garbage ruleset yields no coverage rather than throwing", () => {
  for (const input of ["", "not xml at all", "<group></group>"]) {
    const c = parse(input);
    assert.deepEqual(c.byTechnique, {});
    assert.equal(c.ruleCount, 0);
  }
});

test("an unreadable ruleset reports an error instead of claiming zero coverage", async () => {
  // Inventing a blind spot is as wrong as hiding one — the UI keys off this to
  // render coverage as UNKNOWN.
  const missing = path.join(os.tmpdir(), "definitely-not-here-" + Date.now(), "rules.xml");
  process.env.DASH_RULES_FILE = missing;
  const mod = await import(`../server/coverage.js?missing=${Date.now()}`);
  const r = mod.read();
  assert.ok(r.error, "must surface an error");
  assert.deepEqual(r.byTechnique, {});
  delete process.env.DASH_RULES_FILE;
});

test("a real ruleset file is read and cached by mtime", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dl-cov-"));
  const file = path.join(dir, "local_rules.xml");
  fs.writeFileSync(file, RULES);
  process.env.DASH_RULES_FILE = file;

  const mod = await import(`../server/coverage.js?real=${Date.now()}`);
  const first = mod.read();
  assert.equal(first.detectionCount, 2);
  assert.equal(mod.read(), first, "unchanged file returns the cached object");

  // Editing the ruleset must be picked up without a restart.
  fs.writeFileSync(file, RULES.replace('<id>T1105</id>', '<id>T1105</id><id>T1071.004</id>'));
  const second = mod.read();
  assert.ok(second.byTechnique["T1071.004"], "an edited ruleset is re-read");

  delete process.env.DASH_RULES_FILE;
  fs.rmSync(dir, { recursive: true, force: true });
});

test("the project's own ruleset parses and maps every matrix technique", async () => {
  // Guards the regex against a future edit to the real file — a silent parse
  // failure here would quietly report the whole lab as uncovered.
  const file = path.join(import.meta.dirname, "..", "..",
    "detections", "rules", "local_rules.xml");
  const c = parse(fs.readFileSync(file, "utf8"));
  assert.ok(c.detectionCount >= 15, `expected the real detections, got ${c.detectionCount}`);
  for (const tech of ["T1059.001", "T1053.005", "T1003.001", "T1070.001",
    "T1071.004", "T1105", "T1110", "T1078", "T1021.002"]) {
    assert.ok(c.byTechnique[tech]?.length, `${tech} should have a covering rule`);
  }
});
