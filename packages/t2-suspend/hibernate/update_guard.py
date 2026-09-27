"""Read-only ALPM admission while the qualified source boot policy is inactive.

Presence of boot-policy.json, source-default-activation.pending or
source-default-deactivation.pending in the fixed product state blocks updates,
regardless of contents. Routine opt-in and EFI loader overrides must also be
absent, with efivarfs visible. Future
activation/deactivation must retain evidence elsewhere and exclusively own both
pacman's actual db.lck and the shared physical lock throughout their transition;
this one-shot guard cannot close an independently privileged activation race.

No deactivation, boot writes, automatic rebuild or qualification occurs here.
The fixed root CLI accepts no arguments or environment-based bypass. Explicit
canonical fixture roots are available only to imported offline tests.
"""
import os
from pathlib import Path
import re
import stat
import sys


STATE = Path("var/lib/omarchy/t2-hibernate-product")
EFI = Path("sys/firmware/efi/efivars")
LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
ACTIVE = (STATE / "boot-policy.json", STATE / "source-default-activation.pending",
          STATE / "source-default-deactivation.pending", Path("etc/omarchy/t2-hibernate-product.enabled"),
          EFI / ("LoaderEntryOneShot-" + LOADER_GUID), EFI / ("LoaderEntryDefault-" + LOADER_GUID))
LIMINE = Path("boot/limine.conf")
PRODUCTION = "boot():/EFI/Linux/omarchy_linux-t2.efi"
MAX_BYTES = 1024 * 1024


def _stock(raw):
  """Bind index 2 to the ordinary production child, permitting updated hashes."""
  if len(raw) > MAX_BYTES: raise ValueError("Oversized Limine configuration")
  text = raw.decode("utf-8", errors="strict")
  lines = text.splitlines()
  defaults = [line for line in lines if re.match(r"^[ \t]*default_entry[ \t]*:", line, re.I)]
  if defaults != ["default_entry: 2"]:
    raise ValueError("Inactive updates require canonical stock default 2")
  if any(re.match(r"^[ \t]*remember_last_entry[ \t]*:", line, re.I) for line in lines):
    raise ValueError("Remembered boot selection is outside inactive stock policy")
  entries = [(index, line.strip()) for index, line in enumerate(lines) if line.strip().startswith("/")]
  if len(entries) < 2 or entries[0][1] != "/+Omarchy" or entries[1][1] != "//linux-t2":
    raise ValueError("Stock index 2 must select Omarchy's production linux-t2 child")
  start, end = entries[1][0] + 1, entries[2][0] if len(entries) > 2 else len(lines)
  properties = {}
  for line in lines[start:end]:
    if not line.strip() or line.lstrip().startswith("#"): continue
    if ":" not in line: raise ValueError("Malformed production boot entry")
    key, value = line.strip().split(":", 1)
    key = key.strip().lower()
    if key == "comment": continue
    if key in properties: raise ValueError("Ambiguous production boot entry")
    properties[key] = value.strip()
  if properties.get("protocol") != "efi" or not re.fullmatch(re.escape(PRODUCTION) + r"#[0-9a-f]{128}", properties.get("path", "")):
    raise ValueError("Stock index 2 must use the fixed production UKI path")
  if any(key in properties for key in ("image_path", "kernel_path", "module_path", "chainload_next")):
    raise ValueError("Alternate boot targets are outside inactive stock policy")


def _ancestors(root, path, owner):
  for parent in path.parents:
    try: info = parent.lstat()
    except FileNotFoundError:
      # Ordinary absent state directories are inactive. Existing ancestors
      # must still be checked, including a dangling intermediate symlink.
      continue
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner) or info.st_mode & 0o022:
      raise ValueError("Owned nonsymlink update admission ancestors required")
    if parent == root: break


def check(root):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Explicit canonical update-guard root required")
  owner = 0 if root == Path("/") else os.geteuid()
  if root == Path("/") and os.geteuid() != 0: raise ValueError("Root update admission required")
  for relative in ACTIVE:
    _ancestors(root, root / relative, owner)
    try: (root / relative).lstat()
    except FileNotFoundError: continue
    raise ValueError("T2 source policy or routine hibernation remains active/incomplete: " + str(relative))
  if not stat.S_ISDIR((root / EFI).lstat().st_mode):
    raise ValueError("Visible EFI variable directory required for inactive admission")
  path = root / LIMINE
  _ancestors(root, path, owner)
  initial = path.lstat()
  if not stat.S_ISREG(initial.st_mode): raise ValueError("Regular stock boot configuration required")
  descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or info.st_nlink != 1:
      raise ValueError("Owned regular stock boot configuration required")
    if info.st_size > MAX_BYTES: raise ValueError("Oversized Limine configuration")
    with os.fdopen(descriptor, "rb", closefd=False) as source: raw = source.read(MAX_BYTES + 1)
    _stock(raw)
  finally: os.close(descriptor)
  return {"classification": "inactive-stock-update-admitted", "default_entry": 2}


def main(argv=None):
  arguments = sys.argv[1:] if argv is None else argv
  if arguments: raise ValueError("No update-guard arguments or bypasses permitted")
  if os.geteuid() != 0: raise ValueError("Explicit root update-guard invocation required")
  check(Path("/"))
  return 0


if __name__ == "__main__":
  try: raise SystemExit(main())
  except (OSError, ValueError) as error:
    print("T2 hibernation update guard: " + str(error), file=sys.stderr)
    raise SystemExit(1)
