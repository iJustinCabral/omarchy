"""Read-only exact root-side T2 radio module and firmware inventory.

This covers only the installer's five selected radio modules (the BCE family is
stock-only since package 1.6) and matching Broadcom firmware, not the full hibernation dependency/effect closure or update safety.
Live callers must verify the reviewed installed runtime, supply an audited
kernel release, and own package/physical exclusion throughout capture; fixed
path checking alone is not code review.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess

SOURCE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/root_driver_inventory.py")
MODULES = ("brcmfmac", "brcmfmac-wcc", "brcmfmac-cyw", "brcmfmac-bca", "hci_bcm4377")
FORMOSA = "brcmfmac4377b3-pcie.apple,formosa"
SUFFIXES = (".bin", "-SPPR-m.txt", "-SPPR-u.txt", ".clm_blob", ".txcap_blob")
MAX_FILE = 32 * 1024 * 1024
MAX_FIRMWARE = 64
MAX_TOTAL = 128 * 1024 * 1024
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}


def _query(argv):
  result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10, env=ENV)
  if result.returncode or len(result.stdout.encode()) > 4096 or len(result.stderr.encode()) > 4096:
    raise ValueError("Bounded module query failed")
  return result.stdout.strip()


def _ancestors(root, path, owner):
  for directory in path.parents:
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
      raise ValueError("Owned nonsymlink inventory ancestry required")
    if directory == root: break


def _identity(info):
  return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
          info.st_mode, info.st_uid, info.st_nlink)


def _file(root, path, owner, *, allow_empty=False, allow_hardlinks=False):
  """Stable bounded digest; multi-link regular files are refused unless explicitly allowed (baseline capture)."""
  _ancestors(root, path, owner)
  named = path.lstat()
  if (not stat.S_ISREG(named.st_mode) or named.st_uid != owner or named.st_mode & 0o022 or
      (named.st_nlink != 1 and not allow_hardlinks) or not (0 if allow_empty else 1) <= named.st_size <= MAX_FILE):
    raise ValueError("Bounded owned regular driver bytes required")
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    opened = os.fstat(fd)
    if _identity(opened) != _identity(named): raise ValueError("Driver file changed before read")
    digest = hashlib.sha256()
    count = 0
    while True:
      raw = os.read(fd, min(1024 * 1024, MAX_FILE + 1 - count))
      if not raw: break
      count += len(raw)
      if count > MAX_FILE: raise ValueError("Driver file exceeded size bound")
      digest.update(raw)
    if count != opened.st_size or _identity(os.fstat(fd)) != _identity(opened) or _identity(path.lstat()) != _identity(opened):
      raise ValueError("Short or changed driver read")
    value = {"size": count, "sha256": digest.hexdigest()}
    if allow_hardlinks: value["nlink"] = opened.st_nlink
    return value
  finally: os.close(fd)


def _selected(root, release, name, selected):
  if type(selected) is not str or not 0 < len(selected) <= 4096 or "\n" in selected or "\r" in selected or "\0" in selected:
    raise ValueError("Single exact modinfo selection required")
  if selected.startswith("//") and (root != Path("/") or not selected.startswith("//lib/modules/")):
    raise ValueError("Only native double-slash /lib selection is recognized")
  path = PurePosixPath(selected)
  if not path.is_absolute() or ".." in path.parts or str(path) != selected:
    raise ValueError("Canonical absolute modinfo selection required")
  if root != Path("/"):
    try: relative = Path(selected).relative_to(root).as_posix()
    except ValueError: raise ValueError("Fixture modinfo selection escaped its root") from None
  else:
    relative = selected.lstrip("/")
  if relative.startswith("lib/modules/"):
    relative = "usr/" + relative
  prefix = "usr/lib/modules/" + release + "/"
  if not relative.startswith(prefix): raise ValueError("Selected module outside exact kernel tree")
  basename = PurePosixPath(relative).name
  stems = (name, name.replace("-", "_"))
  if basename not in {stem + ".ko" + ext for stem in stems for ext in ("", ".zst", ".xz", ".gz")}:
    raise ValueError("Modinfo selected another module")
  return root / relative


def _firmware_target(root, path, owner):
  tree = root / "usr/lib/firmware"
  links = []
  current = path
  for _ in range(9):
    if not current.is_relative_to(tree): raise ValueError("Firmware link escaped its root tree")
    _ancestors(root, current, owner)
    info = current.lstat()
    if not stat.S_ISLNK(info.st_mode):
      return current, links
    if info.st_uid != owner: raise ValueError("Unowned firmware link")
    target = os.readlink(current)
    if not target or "\0" in target: raise ValueError("Invalid firmware link")
    links.append((current, _identity(info), target))
    if target.startswith("/"):
      normalized = posixpath.normpath(target).lstrip("/")
    else:
      normalized = posixpath.normpath(str(current.parent.relative_to(root)) + "/" + target)
    if not normalized.startswith("usr/lib/firmware/"):
      raise ValueError("Firmware link escaped its root tree")
    current = root / normalized
  raise ValueError("Firmware link chain exceeds bound")


def _firmware(root, path, owner, allow_hardlinks=False):
  target, links = _firmware_target(root, path, owner)
  value = _file(root, target, owner, allow_hardlinks=allow_hardlinks)
  for link, identity, text in links:
    if _identity(link.lstat()) != identity or os.readlink(link) != text:
      raise ValueError("Firmware link changed during read")
  return {"selected": "/" + path.relative_to(root).as_posix(),
          "target": "/" + target.relative_to(root).as_posix(),
          "links": [{"path": "/" + link.relative_to(root).as_posix(), "target": text} for link, _, text in links],
          **value}


def _prepare(root, kernel_release, query):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Canonical explicit inventory root required")
  if root == Path("/"):
    if os.geteuid() != 0 or query is not None or Path(__file__).absolute() != SOURCE:
      raise ValueError("Only reviewed installed live inventory may run")
  elif query is None:
    raise ValueError("Synthetic inventory requires explicit query fixture")
  if (type(kernel_release) is not str or kernel_release in (".", "..") or
      not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", kernel_release)):
    raise ValueError("Exact kernel release required")
  owner = 0 if root == Path("/") else os.geteuid()
  alias = root / "lib"
  info = alias.lstat()
  if not stat.S_ISLNK(info.st_mode) or info.st_uid != owner or os.readlink(alias) != "usr/lib":
    raise ValueError("Exact /lib to usr/lib alias required")
  for directory in (root / "usr/lib/modules" / kernel_release, root / "usr/lib/firmware/brcm"):
    _ancestors(root, directory / "member", owner)
  return root, owner, alias, info, (_query if query is None else query)


def _modules(root, kernel_release, owner, query, total, hardlinks):
  modules = {}
  for name in MODULES:
    selected = query(("/usr/bin/modinfo", "-b", str(root), "-k", kernel_release, "-n", name))
    path = _selected(root, kernel_release, name, selected)
    value = _file(root, path, owner, allow_hardlinks=hardlinks)
    source = query(("/usr/bin/modinfo", "-F", "srcversion", str(path)))
    vermagic = query(("/usr/bin/modinfo", "-F", "vermagic", str(path)))
    if not re.fullmatch(r"[0-9A-Fa-f]{8,64}", source) or len(vermagic) > 4096 or "\n" in vermagic or not vermagic.split() or vermagic.split()[0] != kernel_release:
      raise ValueError("Selected module source/ABI differs")
    if (query(("/usr/bin/modinfo", "-b", str(root), "-k", kernel_release, "-n", name)) != selected or
        _file(root, path, owner, allow_hardlinks=hardlinks) != value):
      raise ValueError("Selected module changed during metadata query")
    modules[name] = {"selected": "/" + path.relative_to(root).as_posix(), "srcversion": source,
                     "vermagic": vermagic, **value}
    total += value["size"]
    if total > MAX_TOTAL: raise ValueError("Root-side driver inventory exceeds total bound")
  return modules, total


def _firmware_set(root, owner, total, hardlinks):
  directory = root / "usr/lib/firmware/brcm"
  names = sorted(entry.name for entry in directory.iterdir() if entry.name.startswith("brcmfmac4377b3-"))
  if len(names) > MAX_FIRMWARE or not set(FORMOSA + suffix for suffix in SUFFIXES).issubset(names):
    raise ValueError("Complete required Formosa firmware set required")
  firmware = {}
  for name in names:
    firmware[name] = _firmware(root, directory / name, owner, hardlinks)
    total += firmware[name]["size"]
    if total > MAX_TOTAL: raise ValueError("Root-side driver inventory exceeds total bound")
  if sorted(entry.name for entry in directory.iterdir() if entry.name.startswith("brcmfmac4377b3-")) != names:
    raise ValueError("Firmware name set changed during capture")
  return firmware, directory, total


def _recheck_modules(root, kernel_release, owner, query, modules, hardlinks):
  for name, recorded in modules.items():
    selected = query(("/usr/bin/modinfo", "-b", str(root), "-k", kernel_release, "-n", name))
    path = _selected(root, kernel_release, name, selected)
    keys = ("size", "sha256", "nlink") if hardlinks else ("size", "sha256")
    if "/" + path.relative_to(root).as_posix() != recorded["selected"] or _file(root, path, owner, allow_hardlinks=hardlinks) != {key: recorded[key] for key in keys}:
      raise ValueError("Module selection or bytes changed across inventory")


def _recheck_firmware(directory, owner, root, firmware, hardlinks):
  for name, recorded in firmware.items():
    if _firmware(root, directory / name, owner, hardlinks) != recorded:
      raise ValueError("Firmware selection or bytes changed across inventory")


def _alias_stable(alias, info):
  if os.readlink(alias) != "usr/lib" or alias.lstat().st_ino != info.st_ino:
    raise ValueError("/lib alias changed during capture")


def capture(root, kernel_release, query=None):
  """Return deterministic partial bytes/selection inventory, never a safety verdict."""
  root, owner, alias, info, query = _prepare(root, kernel_release, query)
  modules, total = _modules(root, kernel_release, owner, query, 0, False)
  firmware, directory, total = _firmware_set(root, owner, total, False)
  _recheck_modules(root, kernel_release, owner, query, modules, False)
  _recheck_firmware(directory, owner, root, firmware, False)
  _alias_stable(alias, info)
  return {"protocol": "omarchy-t2-root-driver-inventory-v1", "kernel_release": kernel_release,
          "lib_alias": "usr/lib", "modules": modules, "firmware": firmware}


def capture_baseline(root, kernel_release, query=None):
  """Baseline capture: modules and firmware fail independently and multi-link files are accepted.

  Same ownership, mode, regular-file, size, O_NOFOLLOW and stable-read rules as
  capture(), but a regular file may have several links (real Broadcom firmware
  is hardlinked) and its link count is recorded. Returns
  {"kernel_release", "modules", "firmware", "errors"}: a part that failed is
  None with its reason in errors, so one never discards the other. Preconditions
  (root, release, /lib alias) still raise.
  """
  root, owner, alias, info, query = _prepare(root, kernel_release, query)
  result = {"kernel_release": kernel_release, "modules": None, "firmware": None, "errors": {}}
  total = 0
  try:
    modules, total = _modules(root, kernel_release, owner, query, 0, True)
    _recheck_modules(root, kernel_release, owner, query, modules, True)
    _alias_stable(alias, info)
    result["modules"] = modules
  except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
    result["errors"]["modules"] = type(error).__name__ + ": " + str(error)[:200]
    total = 0
  try:
    firmware, directory, _ = _firmware_set(root, owner, total, True)
    _recheck_firmware(directory, owner, root, firmware, True)
    _alias_stable(alias, info)
    result["firmware"] = firmware
  except (OSError, ValueError, KeyError) as error:
    result["errors"]["firmware"] = type(error).__name__ + ": " + str(error)[:200]
  return result
