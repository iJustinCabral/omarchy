#!/usr/bin/python3
"""Read-only exact pre-architecture controlled-abort witness audit.

An exclusive MBAR witness attests recovery after swsusp_arch_resume entry was
intentionally aborted. It does not prove architecture image copying, atomic
restoration, resumed source userspace, or successful hibernation.
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("pre_arch_return_audit", Path(__file__).with_name("audit-cold-pre-cpu-return.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

if __name__ == "__main__":
  reader.main(required_protocol="cold_pre_arch")
