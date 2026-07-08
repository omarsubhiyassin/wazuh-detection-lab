#!/usr/bin/env python3
"""Synthetic log generator for the detection lab.

Writes real-format logs (sshd auth.log, Windows Event JSON, Suricata eve.json)
mixing benign baseline noise with MITRE ATT&CK-mapped attack scenarios, plus a
ground_truth.jsonl of labels the validation harness scores against.

Examples
--------
  # 6h historical window, all scenarios, reproducible:
  python generate.py --hours 6 --seed 1337

  # only two scenarios, no baseline:
  python generate.py --scenarios brute_force_success,dns_beacon --no-baseline

  # live demo, 60x sped up:
  python generate.py --mode stream --compression 60
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import baseline
from scenarios import engine
from timeline import Timeline
from world import World

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "output"
DEFAULT_GT = HERE / "ground_truth" / "ground_truth.jsonl"
SINKS = ["auth.log", "windows_events.json", "eve.json"]


def parse_args(argv: list[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=1337, help="RNG seed (reproducible output)")
    ap.add_argument("--mode", choices=["backfill", "stream"], default="backfill",
                    help="backfill = historical window written at once; stream = real-time replay")
    ap.add_argument("--hours", type=float, default=6.0, help="length of the generation window")
    ap.add_argument("--compression", type=float, default=60.0,
                    help="stream mode: sim-seconds per real-second (60 = 1 min/sec)")
    ap.add_argument("--scenarios", default="all",
                    help="comma-separated scenario names, or 'all'")
    ap.add_argument("--no-baseline", action="store_true", help="skip benign background noise")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="output directory for log files")
    ap.add_argument("--ground-truth", type=Path, default=DEFAULT_GT, help="ground-truth jsonl path")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    args.ground_truth.parent.mkdir(parents=True, exist_ok=True)

    world = World(args.seed)
    tl = Timeline()
    window = args.hours * 3600.0
    end = time.time()
    start = end - window

    if not args.no_baseline:
        baseline.generate(world, tl, start, window)

    only = None if args.scenarios == "all" else [s.strip() for s in args.scenarios.split(",")]
    playbooks = engine.load_playbooks(only)
    if only and not playbooks:
        print(f"error: no scenarios matched {only}", file=sys.stderr)
        return 2

    # Place each scenario at a spread-out offset in the middle of the window,
    # away from the edges so the burst/beacon fits inside.
    k = len(playbooks)
    for i, cfg in enumerate(playbooks):
        base = window * (i + 1) / (k + 1)
        offset = base + world.rng.uniform(-window * 0.05, window * 0.05)
        engine.build(cfg, world, tl, max(0.0, offset))

    if args.mode == "backfill":
        counts = tl.write_backfill(start, args.out, args.ground_truth, SINKS)
    else:
        counts = tl.write_stream(args.out, args.ground_truth, args.compression, SINKS)

    print(f"Mode        : {args.mode}  (seed={args.seed}, window={args.hours}h)")
    print(f"Scenarios   : {', '.join(c['name'] for c in playbooks)}")
    print(f"Output dir  : {args.out}")
    for sink in SINKS:
        print(f"  {sink:22s}: {counts.get(sink, 0)} lines")
    print(f"Ground truth: {counts.get('ground_truth', 0)} labels -> {args.ground_truth}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
