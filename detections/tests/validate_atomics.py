#!/usr/bin/env python3
"""Validate the detection <-> Atomic Red Team mapping. Runs in CI, hermetic.

The mapping (detections/atomics/coverage.yml) is only worth anything if it stays
true, and there are three ways it silently rots:

  1. a new detection rule is added and nobody maps it -> a capability we cannot
     validate and do not notice;
  2. a GUID is typo'd or invented -> the live runner tries to execute a test
     that does not exist, or worse, a different one;
  3. a mapping points at a platform the atomic does not support -> it never
     triggers and the "validation" is vacuous.

This checks all three against ground truth: every detection rule in
local_rules.xml is either mapped or explicitly exempted; every GUID a mapping
names exists in the pinned ART snapshot (index.snapshot.json, built from real
Atomic Red Team data) under the stated technique; and the platform matches.

It does NOT run atomics. That is inherently live — see Invoke-AtomicValidation.ps1.

Run: python3 detections/tests/validate_atomics.py
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "detections" / "rules" / "local_rules.xml"
COVERAGE = ROOT / "detections" / "atomics" / "coverage.yml"
SNAPSHOT = ROOT / "detections" / "atomics" / "index.snapshot.json"
RUNNER = ROOT / "detections" / "atomics" / "Invoke-AtomicValidation.ps1"

GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def detection_rules(xml_text: str):
    """Our own detections: level > 0, not a vendor overwrite, not scaffolding.

    Mirrors the coverage-view logic. A detection is something we authored that
    should fire on a technique — so level-0 base rules, suppression rules, and
    `overwrite="yes"` vendor recalibrations are all excluded, since none of them
    is a capability an atomic would validate.
    """
    root = ET.fromstring("<root>" + xml_text + "</root>")
    referenced = set()
    for r in root.iter("rule"):
        for tag in ("if_sid", "if_matched_sid"):
            for s in (r.findtext(tag) or "").split(","):
                if s.strip():
                    referenced.add(s.strip())

    out = {}
    for r in root.iter("rule"):
        rid = r.get("id", "")
        if r.get("overwrite", "").lower() == "yes":
            continue
        if int(r.get("level", "0")) <= 0:
            continue
        # A rule with no MITRE mapping is not something an atomic validates.
        mitre = [m.text for m in r.findall("./mitre/id") if m.text]
        if not mitre:
            continue
        out[rid] = mitre
    return out


def main() -> int:
    for p in (RULES, COVERAGE, SNAPSHOT):
        if not p.exists():
            print(f"ERROR: missing {p}", file=sys.stderr)
            return 2

    rules = detection_rules(RULES.read_text(encoding="utf-8"))
    cov = yaml.safe_load(COVERAGE.read_text(encoding="utf-8"))
    snap = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    techniques = snap.get("techniques", {})

    mapped = {m["rule"]: m for m in cov.get("mapped", [])}
    exempt = {e["rule"]: e for e in cov.get("exempt", [])}
    errors = []

    # 1. Every detection is accounted for, and nothing is double-booked.
    for rid in rules:
        if rid not in mapped and rid not in exempt:
            errors.append(f"rule {rid} ({','.join(rules[rid])}) is neither mapped to an "
                          "atomic nor exempted — every detection must be accounted for.")
    for rid in set(mapped) & set(exempt):
        errors.append(f"rule {rid} is both mapped and exempt — pick one.")

    # 2. Mappings point at rules that actually exist as detections.
    for rid in set(mapped) | set(exempt):
        if rid not in rules:
            errors.append(f"coverage.yml references rule {rid}, which is not a current "
                          "detection (renamed, deleted, or level-0?).")

    # 3. Snapshot ref matches what the mapping claims to be pinned to.
    if snap.get("_ref") != cov.get("meta", {}).get("atomic_red_team_ref"):
        errors.append("coverage.yml meta.atomic_red_team_ref does not match the snapshot _ref "
                      "— the mapping and the vendored snapshot are out of sync.")

    # 4. Every mapped GUID is real: well-formed, present in the snapshot under
    #    the stated technique, and supporting the stated platform.
    for rid, m in mapped.items():
        a = m.get("atomic", {})
        guid = str(a.get("guid", ""))
        tech = a.get("technique")
        platform = m.get("platform")
        where = f"rule {rid} atomic {guid}"

        if not GUID_RE.match(guid):
            errors.append(f"{where}: not a valid GUID.")
            continue
        t = techniques.get(tech)
        if not t:
            errors.append(f"{where}: technique {tech} is not in the snapshot — extend the "
                          "snapshot or fix the mapping.")
            continue
        test = t["tests"].get(guid)
        if not test:
            errors.append(f"{where}: GUID not found under {tech} in the ART snapshot "
                          "(typo, invented, or from a different technique).")
            continue
        if platform and platform not in test["platforms"]:
            errors.append(f"{where}: mapping says platform '{platform}' but the atomic "
                          f"'{test['name']}' supports {test['platforms']}.")

    # 5. Exemptions must state WHY and how the rule is otherwise validated — an
    #    unexplained exemption is just an unvalidated detection with cover.
    for rid, e in exempt.items():
        if len((e.get("reason") or "").strip()) < 20:
            errors.append(f"rule {rid}: exemption needs a real reason.")
        if not (e.get("validated_by") or "").strip():
            errors.append(f"rule {rid}: exemption must say how the rule IS validated instead.")

    # 6. The live runner hardcodes the (rule, guid) list for the endpoint, and
    #    the header claims CI keeps it in sync with coverage.yml. Enforce that,
    #    or the claim is a lie: parse the PS1's pscustomobject rows and require
    #    they exactly match the mapped set.
    if RUNNER.exists():
        text = RUNNER.read_text(encoding="utf-8")
        runner_pairs = set(re.findall(
            r"Rule='(\d+)';\s*Technique='[^']+';\s*Guid='([0-9a-f-]+)'", text))
        mapped_pairs = {(rid, str(m["atomic"]["guid"])) for rid, m in mapped.items()}
        if runner_pairs != mapped_pairs:
            for pair in mapped_pairs - runner_pairs:
                errors.append(f"Invoke-AtomicValidation.ps1 is missing mapped atomic {pair}.")
            for pair in runner_pairs - mapped_pairs:
                errors.append(f"Invoke-AtomicValidation.ps1 has {pair}, not in coverage.yml mapped.")
    else:
        errors.append(f"missing live runner {RUNNER.name} that coverage.yml refers to.")

    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)
    if errors:
        print(f"\n{len(errors)} problem(s)", file=sys.stderr)
        return 1

    print(f"atomic mapping OK: {len(rules)} detections "
          f"({len(mapped)} mapped to atomics, {len(exempt)} exempted), "
          f"all GUIDs verified against ART {snap.get('_ref','?')[:12]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
