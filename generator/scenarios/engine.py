"""Load YAML playbooks and dispatch to the matching builder."""
from __future__ import annotations

from pathlib import Path

import yaml

from scenarios.builders import BUILDERS
from timeline import Timeline
from world import World

SCENARIO_DIR = Path(__file__).resolve().parent


def load_playbooks(only: list[str] | None = None) -> list[dict]:
    """Read every *.yaml playbook, optionally filtered to a set of names."""
    playbooks = []
    for path in sorted(SCENARIO_DIR.glob("*.yaml")):
        cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
        cfg["_path"] = str(path)
        if cfg.get("kind") not in BUILDERS:
            raise ValueError(f"{path.name}: unknown kind {cfg.get('kind')!r}")
        if only and cfg["name"] not in only:
            continue
        playbooks.append(cfg)
    return playbooks


def build(cfg: dict, world: World, tl: Timeline, start: float) -> None:
    BUILDERS[cfg["kind"]](cfg, world, tl, start)
