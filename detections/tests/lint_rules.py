#!/usr/bin/env python3
"""Static checks on local_rules.xml, focused on SUPPRESSION rules.

Why this exists as a separate lint rather than a logtest case:

    wazuh-logtest cannot reach the native `windows_eventchannel` decoder — it
    always falls back to the XML `json` decoder — so any rule anchored on a
    vendor rule in the sysmon_event_N group tree (which is the whole eventchannel
    leg of our dual-base pattern) is unreachable from the harness. Verified by
    sweeping `-l EventChannel|WinEvtLog|...`: the decoder stays `json` every time.

    That leaves suppression rules with no behavioural test in CI. The realistic
    regression is not that a suppression stops working, it is that someone
    *loosens* it later — drops a field condition, widens a regex to `.*` — and
    quietly creates a blind spot that nothing alerts on by definition. These
    checks make that fail the build.

Run: python3 detections/tests/lint_rules.py
"""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RULES = Path(__file__).resolve().parents[1] / "rules" / "local_rules.xml"
LOCAL_ID_MIN = 100000  # our own rule ID range; anything below is vendor

# Regex fragments that make a field condition effectively meaningless.
TOO_BROAD = re.compile(r"^\(\?i\)?\)?[\.\*\+\s]*$|^\.[\*\+]$|^\(\?i\)\.[\*\+]$")


def load(path: Path) -> ET.Element:
    """Parse the multi-root Wazuh fragment by wrapping it in a synthetic root."""
    return ET.fromstring("<root>" + path.read_text(encoding="utf-8") + "</root>")


def referenced_parents(root: ET.Element) -> set:
    """Rule IDs that other rules hang off via <if_sid>/<if_matched_sid>.

    Distinguishes the two kinds of level-0 rule in this ruleset. A BASE rule
    (the dual-decoder anchors, e.g. 100610 on Security 1102) is level 0 because
    it is scaffolding for detections built on top of it. A SUPPRESSION rule is
    level 0 because it silences. Only the latter should be linted as a
    suppression — the difference is whether anything is built on it.
    """
    out = set()
    for rule in root.iter("rule"):
        for tag in ("if_sid", "if_matched_sid"):
            for s in (rule.findtext(tag) or "").split(","):
                s = s.strip()
                if s:
                    out.add(s)
    return out


def main() -> int:
    if not RULES.exists():
        print(f"ERROR: {RULES} not found", file=sys.stderr)
        return 2

    root = load(RULES)
    errors, checked = [], 0
    parents_of_something = referenced_parents(root)

    # Map each rule to the name of the <group> element enclosing it.
    for grp in root.findall("group"):
        grp_name = grp.get("name", "")
        for rule in grp.findall("rule"):
            rid = rule.get("id", "?")
            level = int(rule.get("level", "-1"))
            if_sid = (rule.findtext("if_sid") or "").strip()
            fields = rule.findall("field")

            # A level-0 rule whose parent is a VENDOR rule is a suppression: it
            # silences an alert that would otherwise fire.
            parents = [s.strip() for s in if_sid.split(",") if s.strip()]
            vendor_parents = [p for p in parents if p.isdigit() and int(p) < LOCAL_ID_MIN]
            if level != 0 or not vendor_parents:
                continue
            # Scaffolding for other detections, not a suppression.
            if rid in parents_of_something:
                continue

            checked += 1
            where = f"rule {rid} (suppresses vendor {','.join(vendor_parents)})"

            if len(fields) < 2:
                errors.append(
                    f"{where}: only {len(fields)} field condition(s). A suppression must pin "
                    "BOTH the writing process and the artefact, or it will be inherited by "
                    "anything that looks vaguely similar.")

            for f in fields:
                pattern = (f.text or "").strip()
                if not pattern or TOO_BROAD.match(pattern):
                    errors.append(
                        f"{where}: field '{f.get('name')}' has an effectively unbounded "
                        f"pattern {pattern!r} — that suppresses the whole vendor rule.")

            if "tuning" not in grp_name:
                errors.append(
                    f"{where}: must live in a group tagged 'tuning' so suppressions are "
                    f"auditable in one place (found group name {grp_name!r}).")

            desc = (rule.findtext("description") or "").strip()
            if len(desc) < 20:
                errors.append(f"{where}: needs a description explaining what is being silenced.")

            # The comment above the rule should state the residual risk. Checked
            # textually below, since comments are not in the element tree.

    # Every suppression rule must have a RESIDUAL RISK note in the file.
    text = RULES.read_text(encoding="utf-8")
    if checked and "RESIDUAL RISK" not in text:
        errors.append(
            "at least one suppression rule exists but no 'RESIDUAL RISK' note was found. "
            "A suppression with no stated blind spot has not been thought through.")

    for e in errors:
        print(f"FAIL: {e}", file=sys.stderr)

    if errors:
        print(f"\n{len(errors)} problem(s) in {checked} suppression rule(s)", file=sys.stderr)
        return 1

    print(f"suppression lint OK ({checked} suppression rule(s) checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
