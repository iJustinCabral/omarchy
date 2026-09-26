#!/usr/bin/python3
"""Read-only exact pre-syscore returned-witness audit; never a restore claim."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("pre_syscore_return_audit", Path(__file__).with_name("audit-cold-pre-cpu-return.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

if __name__ == "__main__":
  reader.main(required_protocol="cold_pre_syscore")
