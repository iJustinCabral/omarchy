#!/usr/bin/env python3
"""Synthetic tests for the read-only Linux hibernation swap-header auditor."""

from importlib.machinery import SourceFileLoader
import importlib.util
from pathlib import Path
import struct
import tempfile


SCRIPT = Path(__file__).resolve().parents[1] / "experiments/audit-hibernation-swap-header.py"
spec = importlib.util.spec_from_loader("audit_hibernation_swap_header", SourceFileLoader("audit_hibernation_swap_header", str(SCRIPT)))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def page(flags, signature=b"SWAPSPACE2", original=b"SWAPSPACE2"):
  data = bytearray(audit.PAGE_SIZE)
  struct.pack_into(audit.HEADER_FORMAT, data, audit.PAGE_SIZE - audit.HEADER_SIZE,
                   0, 0xE1267FDC, 1923215, flags, original, signature)
  return bytes(data)


platform = audit.parse_header(page(0x5))
assert platform["marker"] == "normal-swap-signature"
assert platform["flags"] == 0x5
assert platform["platform_mode_flag"] is True
assert platform["crc32_flag"] is True
assert platform["first_map_page"] == 1923215

shutdown = audit.parse_header(page(0x4, b"S1SUSPEND\0"))
assert shutdown["marker"] == "hibernation-image-present"
assert shutdown["platform_mode_flag"] is False
assert shutdown["crc32_flag"] is True
assert shutdown["page_sha256"] != platform["page_sha256"]

assert audit.parse_header(page(0, b"not-a-swap"))["marker"] == "unrecognized-signature"
try:
  audit.parse_header(b"too short")
except ValueError:
  pass
else:
  raise AssertionError("A short header page was accepted")

with tempfile.TemporaryDirectory(prefix="t2-swap-header-") as directory:
  fixture = Path(directory) / "device"
  fixture.write_bytes(bytes(audit.PAGE_SIZE * 2) + page(0x5))
  assert audit.read_header(fixture, 2) == platform
  try:
    audit.read_header(fixture, -1)
  except ValueError:
    pass
  else:
    raise AssertionError("A negative resume offset was accepted")
  try:
    audit.read_header(fixture, 3)
  except ValueError:
    pass
  else:
    raise AssertionError("An incomplete device read was accepted")

print("PASS: read-only swap-header audit distinguishes persistent flags from active image signature")
