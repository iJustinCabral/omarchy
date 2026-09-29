#!/usr/bin/python3
"""Pure audit of resolved mkinitcpio hook order for the cold pre-CPU mode."""
import re
from pathlib import Path
import sys

CHAIN = ["omarchy-t2-cold-pre-cpu", "omarchy-t2-restore-marker", "resume", "omarchy-t2-cold-pre-cpu-return"]

def audit_config(config):
  arrays = {}
  for name in ("HOOKS", "EARLYHOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"):
    matches = re.findall(r'^' + name + r'="([^"]*)"$', config, re.M)
    if len(matches) != 1:
      raise ValueError("Missing or duplicate resolved " + name)
    arrays[name] = matches[0].split()
  hooks = arrays["HOOKS"]
  if any(hooks.count(name) != 1 for name in ["encrypt", *CHAIN]):
    raise ValueError("Cold diagnostic requires exactly one encrypt/pre/marker/resume/return hook")
  start = hooks.index(CHAIN[0])
  if hooks[start:start + len(CHAIN)] != CHAIN or hooks.index("encrypt") >= start:
    raise ValueError("Cold diagnostic chain must follow encrypt; marker remains immediately before resume")
  for name, values in arrays.items():
    if name != "HOOKS" and set(values).intersection(CHAIN):
      raise ValueError("Cold diagnostic hooks must occur only as regular hooks")
  return arrays

if __name__ == "__main__":
  audit_config(Path(sys.argv[1]).read_text())
