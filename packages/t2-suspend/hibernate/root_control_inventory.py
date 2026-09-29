"""Exact read-only inventory of a fixed, partial root-side control scope.

Includes sleep/unit overrides, initcpio/config/presets, kmod configuration,
unlock tables (never their referenced keys), Limine generation controls and the
installer's Bluetooth/radio gates. No configuration is evaluated or executed.
The complete module set, binaries/shared libraries (except fixed systemd-sleep
and Bluetooth gate bytes), package/scriptlet effects and key material are NOT
covered. This is not update permission, dependency closure or qualification.

Callers must verify the reviewed installed runtime and hold package/physical
exclusion throughout capture. Two identical reads detect observed changes, not
an atomic filesystem snapshot. Live entry requires the fixed installed path.
"""
import importlib.util
import os
from pathlib import Path
import posixpath
import stat

spec = importlib.util.spec_from_file_location("control_driver_bytes", Path(__file__).with_name("root_driver_inventory.py"))
DRIVER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DRIVER)
SOURCE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/root_control_inventory.py")
PREFIXES = ("etc", "run", "usr/lib")
UNITS = ("systemd-hibernate.service", "bluetooth.service", "bluetooth-after-wifi.service")
DROPS = (*UNITS, "service", "systemd-.service", "bluetooth-.service", "bluetooth-after-.service")
FILES = tuple(sorted((
  "etc/systemd/sleep.conf", "usr/lib/systemd/sleep.conf", "usr/lib/systemd/systemd-sleep",
  "etc/mkinitcpio.conf", "usr/lib/initcpio/functions", "etc/crypttab", "etc/crypttab.initramfs", "etc/fstab",
  "etc/kernel/cmdline", "usr/lib/kernel/cmdline", "boot/limine.conf", "etc/default/limine",
  "etc/limine-entry-tool.conf", "etc/dkms/framework.conf", "etc/bluetooth/main.conf",
  "etc/NetworkManager/conf.d/99-omarchy-t2-radio.conf", "usr/local/sbin/bluetooth-after-wifi",
  "etc/systemd/system/multi-user.target.wants/bluetooth-after-wifi.service",
  *(prefix + "/systemd/system/" + unit for prefix in PREFIXES for unit in UNITS),
)))
TREES = tuple(sorted((
  *(prefix + "/" + directory for prefix in PREFIXES
    for directory in ("systemd/sleep.conf.d", "modprobe.d", "modules-load.d", "depmod.d")),
  *(prefix + "/systemd/system/" + name + ".d" for prefix in PREFIXES for name in DROPS),
  *(prefix + "/" + directory for prefix in ("etc", "usr/lib")
    for directory in ("systemd/system-sleep", "initcpio/hooks", "initcpio/install", "initcpio/post")),
  "usr/local/lib/modprobe.d", "usr/local/lib/depmod.d", "etc/mkinitcpio.conf.d", "etc/mkinitcpio.d",
  "etc/cmdline.d", "etc/limine-entry-tool.d", "usr/share/limine-entry-tool.d",
  "etc/boot/hooks/pre.d", "etc/boot/hooks/post.d", "etc/dkms/framework.conf.d",
)))
MAX_ENTRIES = 4096
MAX_DEPTH = 8
MAX_TOTAL = 64 * 1024 * 1024


def _owned_directory(path, owner):
  info = path.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
    raise ValueError("Owned nonsymlink control ancestry required")
  return info


def _parents(root, path, owner):
  """Validate existing ancestry before missing-path classification."""
  _owned_directory(root, owner)
  current = root
  for part in path.relative_to(root).parts[:-1]:
    current /= part
    try: _owned_directory(current, owner)
    except FileNotFoundError: return False
  return True


def _allowed(relative):
  return relative in FILES or any(relative == tree or relative.startswith(tree + "/") for tree in TREES)


def _target(root, path, owner, baseline=False):
  links, current = [], path
  for _ in range(9):
    if not _parents(root, current, owner): return current, links, "absent"
    try: info = current.lstat()
    except FileNotFoundError: return current, links, "absent"
    if not stat.S_ISLNK(info.st_mode): return current, links, "present"
    if info.st_uid != owner: raise ValueError("Unowned control link")
    text = os.readlink(current)
    if not text or "\0" in text: raise ValueError("Invalid control link")
    links.append((current, DRIVER._identity(info), text))
    relative = posixpath.normpath(text.lstrip("/") if text.startswith("/") else current.parent.relative_to(root).as_posix() + "/" + text)
    if relative == "dev/null": return root / relative, links, "mask"
    if relative.startswith("../") or not _allowed(relative):
      # Baseline mode records the out-of-scope link text only; it is never followed.
      if baseline: return current, links, "out-of-scope"
      raise ValueError("Control link target outside declared scope")
    current = root / relative
  raise ValueError("Control link chain exceeds bound")


def _node(root, path, owner, budget, *, tree=False, depth=0, baseline=False):
  budget[0] += 1
  if budget[0] > MAX_ENTRIES or depth > MAX_DEPTH: raise ValueError("Control inventory entry/depth bound exceeded")
  if not _parents(root, path, owner): return {"kind": "absent"}
  try: info = path.lstat()
  except FileNotFoundError: return {"kind": "absent"}
  if stat.S_ISDIR(info.st_mode):
    if not tree: raise ValueError("Fixed control file is a directory")
    _owned_directory(path, owner)
    entries = {}
    for member in sorted(path.iterdir(), key=lambda item: item.name):
      if any(ord(char) < 32 or ord(char) == 127 for char in member.name): raise ValueError("Invalid control filename")
      member.name.encode("utf-8", "strict")
      entries[member.name] = _node(root, member, owner, budget, tree=True, depth=depth + 1, baseline=baseline)
    if DRIVER._identity(path.lstat()) != DRIVER._identity(info): raise ValueError("Control directory changed during read")
    return {"kind": "directory", "mode": stat.S_IMODE(info.st_mode), "entries": entries}
  if tree and path.relative_to(root).as_posix() in TREES:
    raise ValueError("Control directory is not a real directory")
  target, links, state = _target(root, path, owner, baseline)
  if state == "present":
    named = target.lstat()
    value = DRIVER._file(root, target, owner, allow_empty=True, allow_hardlinks=baseline)
    if DRIVER._identity(target.lstat()) != DRIVER._identity(named): raise ValueError("Control target changed during read")
    value["mode"] = stat.S_IMODE(named.st_mode)
    budget[1] += value["size"]
    if budget[1] > MAX_TOTAL: raise ValueError("Control inventory byte bound exceeded")
  else:
    value = {"kind": state}
  for link, identity, text in links:
    if DRIVER._identity(link.lstat()) != identity or os.readlink(link) != text:
      raise ValueError("Control link changed during read")
  if state == "out-of-scope":
    return {"kind": "symlink", "links": [{"path": "/" + link.relative_to(root).as_posix(), "target": text} for link, _, text in links],
            "target": {"kind": "out-of-scope"}}
  if links:
    return {"kind": "symlink", "links": [{"path": "/" + link.relative_to(root).as_posix(), "target": text} for link, _, text in links],
            "resolved": "/" + target.relative_to(root).as_posix(), "target": value}
  return {"kind": "file", **value}


def _scan(root, owner, baseline=False):
  budget = [0, 0]
  return {"files": {name: _node(root, root / name, owner, budget, baseline=baseline) for name in FILES},
          "directories": {name: _node(root, root / name, owner, budget, tree=True, baseline=baseline) for name in TREES}}


def capture(root, *, baseline=False):
  """Return deterministic scoped control bytes/selection, never a safe boolean.

  baseline=True (generation baseline only) records a symlink whose target lies
  outside the declared scope as its link text plus an out-of-scope marker
  instead of refusing, without following it, and accepts multi-link regular
  files, recording their link count. The default refuses both.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Canonical explicit control inventory root required")
  if root == Path("/") and (os.geteuid() != 0 or Path(__file__).absolute() != SOURCE):
    raise ValueError("Only reviewed installed live control inventory may run")
  owner = 0 if root == Path("/") else os.geteuid()
  first = _scan(root, owner, baseline)
  if _scan(root, owner, baseline) != first: raise ValueError("Control inventory changed across capture")
  return {"protocol": "omarchy-t2-root-control-inventory-v1", **first}
