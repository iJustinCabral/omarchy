#!/usr/bin/env python3
"""Read the x86-64 Linux hibernation swap header without changing it.

The layout is pinned to the 4 KiB swsusp_header in Linux 7.2.6
kernel/power/swap.c. Saved flags remain historical after a resume check
clears the signature, so compare separately captured before/after records
before attributing a header to a particular hibernation attempt.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct


PAGE_SIZE = 4096
HEADER_FORMAT = "<IIQI10s10s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
HIBERNATE_SIGNATURE = b"S1SUSPEND\0"
SWAP_SIGNATURES = (b"SWAPSPACE2", b"SWAP-SPACE")


def parse_header(page):
  if len(page) != PAGE_SIZE:
    raise ValueError("The swap header page must be exactly 4096 bytes")
  hardware_signature, crc32, first_map_page, flags, original, signature = struct.unpack_from(
    HEADER_FORMAT, page, PAGE_SIZE - HEADER_SIZE
  )
  if signature == HIBERNATE_SIGNATURE:
    marker = "hibernation-image-present"
  elif signature in SWAP_SIGNATURES:
    marker = "normal-swap-signature"
  else:
    marker = "unrecognized-signature"
  return {
    "marker": marker,
    "signature_hex": signature.hex(),
    "original_signature_hex": original.hex(),
    "flags": flags,
    "platform_mode_flag": bool(flags & 0x1),
    "no_compression_flag": bool(flags & 0x2),
    "crc32_flag": bool(flags & 0x4),
    "hardware_signature_flag": bool(flags & 0x8),
    "lz4_flag": bool(flags & 0x10),
    "hardware_signature": hardware_signature,
    "crc32": crc32,
    "first_map_page": first_map_page,
    "page_sha256": hashlib.sha256(page).hexdigest(),
  }


def read_header(device, page_offset):
  if page_offset < 0:
    raise ValueError("Resume page offset must not be negative")
  descriptor = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
  try:
    page = os.pread(descriptor, PAGE_SIZE, page_offset * PAGE_SIZE)
  finally:
    os.close(descriptor)
  return parse_header(page)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--device", type=Path, required=True)
  parser.add_argument("--page-offset", type=int, required=True)
  arguments = parser.parse_args()
  try:
    result = read_header(arguments.device, arguments.page_offset)
  except (OSError, ValueError) as error:
    parser.error(str(error))
  result["device"] = str(arguments.device)
  result["page_offset"] = arguments.page_offset
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
