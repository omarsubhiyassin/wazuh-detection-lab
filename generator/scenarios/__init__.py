"""Attack scenarios: declarative YAML playbooks + Python builders.

Each playbook (``*.yaml``) holds the attack narrative, MITRE mapping, and tunable
parameters. Its ``kind`` selects a builder in ``builders.py`` that emits correlated
events (same host/user/src-IP) onto the Timeline and writes ground-truth labels.
"""
