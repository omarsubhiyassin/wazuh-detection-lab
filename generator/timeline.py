"""Event scheduling, output sinks, and ground-truth labels.

Builders (baseline + scenarios) append *deferred* events to a Timeline as
(offset_seconds, sink, render) where ``render(ts) -> str`` produces the log
line for an absolute timestamp. This lets the same schedule be materialized two
ways:

  * backfill -- resolve every ts = start + offset, render, sort, write. Fast;
    populates the indexer with a historical window instantly.
  * stream   -- replay in real time (scaled by a compression factor), stamping
    each line with the wall-clock time it actually fires. For live demos.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"


@dataclass
class _Event:
    offset: float
    sink: str
    render: Callable[[float], str]


@dataclass
class _Label:
    offset: float
    data: dict


@dataclass
class Timeline:
    events: list[_Event] = field(default_factory=list)
    labels: list[_Label] = field(default_factory=list)
    _eid: int = 0

    # --- population API used by builders ---------------------------------
    def emit(self, offset: float, sink: str, render: Callable[[float], str]) -> None:
        self.events.append(_Event(max(0.0, offset), sink, render))

    def label(self, offset: float, *, technique_id: str, tactic: str, scenario: str,
              host: str, source: str, src_ip: str | None = None,
              expected_rules: list[int] | None = None, note: str = "") -> None:
        self._eid += 1
        self.labels.append(_Label(max(0.0, offset), {
            "event_id": f"gt-{self._eid:06d}",
            "technique_id": technique_id,
            "tactic": tactic,
            "scenario": scenario,
            "host": host,
            "source": source,
            "src_ip": src_ip,
            "expected_rules": expected_rules or [],
            "note": note,
        }))

    # --- materialization -------------------------------------------------
    def write_backfill(self, start: float, out_dir: Path, gt_path: Path,
                       truncate_sinks: list[str]) -> dict:
        for name in truncate_sinks:
            (out_dir / name).write_text("", encoding="utf-8")

        by_sink: dict[str, list[tuple[float, str]]] = defaultdict(list)
        for ev in self.events:
            ts = start + ev.offset
            by_sink[ev.sink].append((ts, ev.render(ts)))

        counts = {}
        for sink, rows in by_sink.items():
            rows.sort(key=lambda r: r[0])
            with (out_dir / sink).open("a", encoding="utf-8") as fh:
                for _, line in rows:
                    fh.write(line + "\n")
            counts[sink] = len(rows)

        gt_rows = sorted(
            ({**lb.data, "timestamp": iso(start + lb.offset), "epoch": round(start + lb.offset, 3)}
             for lb in self.labels),
            key=lambda r: r["epoch"],
        )
        with gt_path.open("w", encoding="utf-8") as fh:
            for row in gt_rows:
                fh.write(json.dumps(row) + "\n")

        counts["ground_truth"] = len(gt_rows)
        return counts

    def write_stream(self, out_dir: Path, gt_path: Path, compression: float,
                     truncate_sinks: list[str]) -> dict:
        for name in truncate_sinks:
            (out_dir / name).write_text("", encoding="utf-8")

        items = sorted(
            [("event", ev.offset, ev) for ev in self.events]
            + [("label", lb.offset, lb) for lb in self.labels],
            key=lambda t: t[1],
        )
        handles: dict[str, object] = {}
        gt_fh = gt_path.open("w", encoding="utf-8")
        counts: dict[str, int] = defaultdict(int)
        t0 = time.time()
        try:
            for kind, offset, obj in items:
                target = t0 + offset / compression
                delay = target - time.time()
                if delay > 0:
                    time.sleep(delay)
                ts = time.time()
                if kind == "event":
                    fh = handles.get(obj.sink)
                    if fh is None:
                        fh = handles[obj.sink] = (out_dir / obj.sink).open("a", encoding="utf-8")
                    fh.write(obj.render(ts) + "\n")
                    fh.flush()
                    counts[obj.sink] += 1
                else:
                    row = {**obj.data, "timestamp": iso(ts), "epoch": round(ts, 3)}
                    gt_fh.write(json.dumps(row) + "\n")
                    gt_fh.flush()
                    counts["ground_truth"] += 1
        finally:
            for fh in handles.values():
                fh.close()
            gt_fh.close()
        return dict(counts)
