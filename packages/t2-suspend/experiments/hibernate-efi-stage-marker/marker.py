#!/usr/bin/python3
"""Pre-arm and inspect one EFI breadcrumb for a guarded T2 S4 vector.

The diagnostic kernel changes stage 0 to 1 at hibernation entry and 1 to 2
after the source snapshot completes. This module never deletes a marker.
"""

import os
from pathlib import Path


VARIABLE = Path("sys/firmware/efi/efivars/OmarchyT2HibernateStage-96234839-90c9-4cd5-97b2-7ba690f0af02")
KERNEL_PARAMETER = Path("sys/module/hibernate/parameters/t2_hibernate_efi_marker")
ATTRIBUTES = (7).to_bytes(4, "little")
MAGIC = b"MBA9"


def payload(vector, stage):
  if len(vector) != 64 or any(character not in "0123456789abcdef" for character in vector):
    raise ValueError("Pair-wide vector must be a lowercase SHA-256 digest")
  if stage not in (0, 1, 2):
    raise ValueError("Unsupported EFI hibernation stage")
  return MAGIC + bytes.fromhex(vector[:24]) + bytes((stage,))


def decode(data, vector):
  if len(data) != 21 or data[:4] != ATTRIBUTES:
    raise ValueError("EFI marker attributes or size differ from the diagnostic contract")
  for stage in (0, 1, 2):
    if data[4:] == payload(vector, stage):
      return stage
  raise ValueError("EFI marker belongs to another vector or has an unknown stage")


def marker_path(root):
  return root / VARIABLE


def parameter_path(root):
  return root / KERNEL_PARAMETER


def inspect(root, vector):
  path = marker_path(root)
  if path.is_symlink():
    raise ValueError("EFI marker path is a symlink")
  if not path.exists():
    return None
  if not path.is_file():
    raise ValueError("EFI marker is not a regular variable")
  return decode(path.read_bytes(), vector)


def require_kernel_available(root):
  path = parameter_path(root)
  if path.is_symlink() or not path.is_file():
    raise ValueError("Running kernel has no T2 EFI stage-marker parameter")


def require_kernel_support(root):
  require_kernel_available(root)
  path = parameter_path(root)
  if path.read_text().strip() not in ("Y", "1"):
    raise ValueError("T2 EFI stage-marker kernel parameter is not enabled")


def enable(root):
  require_kernel_available(root)
  parameter_path(root).write_text("Y")
  require_kernel_support(root)


def prearm(root, vector):
  require_kernel_support(root)
  path = marker_path(root)
  if path.exists() or path.is_symlink():
    raise ValueError("An EFI stage marker already exists; preserve it and do not retry")
  value = ATTRIBUTES + payload(vector, 0)
  flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
  descriptor = os.open(path, flags, 0o600)
  try:
    if os.write(descriptor, value) != len(value):
      raise OSError("Short EFI stage-marker write")
  finally:
    os.close(descriptor)
  if inspect(root, vector) != 0:
    raise ValueError("EFI stage-marker readback did not match the armed vector")
  return str(path)
