#!/usr/bin/python3
"""Read-only MBPG audit: PCI guard recovery plus intentional pre-arch abort.

This exclusive witness does not attest DMA draining, atomic image restoration,
restored source userspace or successful hibernation.
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("cold_pci_return_audit", Path(__file__).with_name("audit-cold-pre-cpu-return.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)

if __name__ == "__main__":
  reader.main(required_protocol="cold_pci_pre_arch")
