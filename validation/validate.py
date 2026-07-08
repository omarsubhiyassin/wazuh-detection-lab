#!/usr/bin/env python3
"""Score detections against ground truth.

Joins the generator's ground_truth.jsonl (what was injected) against the alerts
in the Wazuh indexer (what was detected) and reports, per MITRE technique:
detection rate (recall), false negatives, and false positives. Emits a Markdown
report, a JSON summary, and an ATT&CK-Navigator layer.

An injected event counts as DETECTED if, within +/- --window seconds of its
timestamp, an alert fired whose rule.mitre.id contains the technique OR whose
rule.id is in the label's expected_rules. A false positive is a custom-rule
alert (id >= 100000, level > 0) tagged with a technique that was never injected
in this run (run-order-independent; see score() for why).

Reads the indexer with the read-only account (env or CLI):
  INDEXER_URL, INDEXER_RO_USER, INDEXER_RO_PASSWORD
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_GT = HERE.parent / "generator" / "ground_truth" / "ground_truth.jsonl"
DEFAULT_OUT = HERE / "reports"


def load_ground_truth(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def query_alerts(url: str, user: str, pw: str, index: str,
                 gte_epoch: float, lte_epoch: float) -> list[dict]:
    """Fetch alerts in [gte, lte] (epoch seconds). Uses the sort value for a
    parse-free millisecond timestamp."""
    body = {
        "size": 10000,
        "query": {"range": {"timestamp": {
            "gte": int(gte_epoch * 1000), "lte": int(lte_epoch * 1000),
            "format": "epoch_millis"}}},
        "sort": [{"timestamp": "asc"}],
        "_source": ["timestamp", "rule.id", "rule.level", "rule.mitre.id",
                    "agent.name", "data.srcip", "full_log"],
    }
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{url.rstrip('/')}/{index}/_search", data=data, method="POST",
        headers={"Content-Type": "application/json"})
    auth = __import__("base64").b64encode(f"{user}:{pw}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        payload = json.load(r)
    alerts = []
    for h in payload.get("hits", {}).get("hits", []):
        s = h["_source"]
        rule = s.get("rule", {})
        mitre = rule.get("mitre", {}) or {}
        alerts.append({
            "epoch": (h["sort"][0] / 1000.0) if h.get("sort") else 0.0,
            "rule_id": int(rule.get("id", 0)),
            "level": int(rule.get("level", 0)),
            "mitre_ids": mitre.get("id", []) or [],
            "srcip": (s.get("data", {}) or {}).get("srcip"),
        })
    return alerts


def matches(gt: dict, alert: dict, window: float) -> bool:
    if abs(alert["epoch"] - gt["epoch"]) > window:
        return False
    if gt["technique_id"] in alert["mitre_ids"]:
        return True
    if alert["rule_id"] in set(gt.get("expected_rules", []) or []):
        return True
    return False


def score(gts: list[dict], alerts: list[dict], window: float) -> dict:
    per_tech: dict[str, dict] = defaultdict(
        lambda: {"injected": 0, "detected": 0, "rules": set(), "scenarios": set()})
    detail = []
    for gt in gts:
        t = per_tech[gt["technique_id"]]
        t["injected"] += 1
        t["scenarios"].add(gt.get("scenario", "?"))
        hit_rules = sorted({a["rule_id"] for a in alerts if matches(gt, a, window)})
        detected = bool(hit_rules)
        if detected:
            t["detected"] += 1
            t["rules"].update(hit_rules)
        detail.append({
            "event_id": gt.get("event_id"), "technique": gt["technique_id"],
            "scenario": gt.get("scenario"), "detected": detected,
            "fired_rules": hit_rules,
        })

    # False positives: a custom-rule alert (level>0) tagged with a technique that
    # was never injected in this run. This is deliberately run-order-independent:
    # the shared indexer accumulates alerts across runs, so a time-based "matches
    # no ground-truth event" test would wrongly flag a prior run's (valid) attack
    # alerts. Since the custom rules are verified not to fire on the benign
    # baseline (Phase 3 logtest), a custom alert whose technique WAS injected is a
    # detection, not a false positive; only a non-injected technique is a real FP.
    injected_techs = {gt["technique_id"] for gt in gts}
    fps = [a for a in alerts
           if a["rule_id"] >= 100000 and a["level"] > 0
           and not (set(a["mitre_ids"]) & injected_techs)]

    injected = sum(t["injected"] for t in per_tech.values())
    detected = sum(t["detected"] for t in per_tech.values())
    return {
        "window_seconds": window,
        "totals": {
            "injected": injected, "detected": detected,
            "recall": round(detected / injected, 3) if injected else 0.0,
            "false_negatives": injected - detected,
            "false_positives": len(fps),
        },
        "per_technique": {
            k: {
                "injected": v["injected"], "detected": v["detected"],
                "detection_rate": round(v["detected"] / v["injected"], 3) if v["injected"] else 0.0,
                "rules": sorted(v["rules"]), "scenarios": sorted(v["scenarios"]),
            } for k, v in sorted(per_tech.items())
        },
        "false_positive_rules": sorted({a["rule_id"] for a in fps}),
        "detail": detail,
    }


def write_markdown(result: dict, path: Path) -> None:
    t = result["totals"]
    lines = [
        "# Detection coverage report", "",
        f"- Injected events: **{t['injected']}**",
        f"- Detected: **{t['detected']}**  (recall **{t['recall'] * 100:.0f}%**)",
        f"- False negatives: **{t['false_negatives']}**",
        f"- False positives (custom-rule alert tagged with a non-injected technique): "
        f"**{t['false_positives']}**"
        + (f" — rules {result['false_positive_rules']}" if result["false_positive_rules"] else ""),
        f"- Match window: ±{int(result['window_seconds'])}s", "",
        "## Per technique", "",
        "| Technique | Injected | Detected | Rate | Rules | Scenarios |",
        "|-----------|:--:|:--:|:--:|-------|-----------|",
    ]
    for tech, v in result["per_technique"].items():
        mark = "✅" if v["detection_rate"] == 1 else ("⚠️" if v["detected"] else "❌")
        rules = ", ".join(str(r) for r in v["rules"]) or "—"
        lines.append(f"| {tech} | {v['injected']} | {v['detected']} {mark} | "
                     f"{v['detection_rate'] * 100:.0f}% | {rules} | {', '.join(v['scenarios'])} |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# Colors mirror ATT&CK Navigator convention (red = missed, green = full).
def write_navigator(result: dict, path: Path) -> None:
    techniques = []
    for tech, v in result["per_technique"].items():
        rate = v["detection_rate"]
        color = "#2ca02c" if rate >= 1 else ("#d9d900" if rate > 0 else "#e60000")
        techniques.append({
            "techniqueID": tech, "score": round(rate * 100),
            "color": color, "enabled": True,
            "comment": f"{v['detected']}/{v['injected']} detected"
                       + (f" by {v['rules']}" if v["rules"] else ""),
        })
    layer = {
        "name": "Detection Lab Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Measured detection coverage from the synthetic-log validation run.",
        "techniques": techniques,
        "gradient": {"colors": ["#e60000", "#d9d900", "#2ca02c"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "detected (100%)", "color": "#2ca02c"},
            {"label": "partial", "color": "#d9d900"},
            {"label": "missed (0%)", "color": "#e60000"},
        ],
    }
    path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--window", type=float, default=120.0, help="match window (seconds)")
    ap.add_argument("--pad", type=float, default=300.0, help="query range padding (seconds)")
    ap.add_argument("--index", default=os.environ.get("ALERTS_INDEX", "wazuh-alerts-*"))
    ap.add_argument("--url", default=os.environ.get("INDEXER_URL", "https://localhost:9200"))
    ap.add_argument("--user", default=os.environ.get("INDEXER_RO_USER", "detectionlab_ro"))
    ap.add_argument("--password", default=os.environ.get("INDEXER_RO_PASSWORD", ""))
    args = ap.parse_args(argv)

    if not args.ground_truth.exists():
        print(f"error: ground truth not found: {args.ground_truth}", file=sys.stderr)
        return 2
    gts = load_ground_truth(args.ground_truth)
    if not gts:
        print("error: ground truth is empty", file=sys.stderr)
        return 2

    epochs = [g["epoch"] for g in gts]
    alerts = query_alerts(args.url, args.user, args.password, args.index,
                          min(epochs) - args.pad, max(epochs) + args.pad)

    result = score(gts, alerts, args.window)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "coverage.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    write_markdown(result, args.out / "coverage.md")
    write_navigator(result, args.out / "attack-navigator-layer.json")

    t = result["totals"]
    print(f"injected={t['injected']} detected={t['detected']} "
          f"recall={t['recall'] * 100:.0f}% FN={t['false_negatives']} FP={t['false_positives']}")
    print(f"alerts queried in window: {len(alerts)}")
    print(f"reports -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
