"""Reviewed desktop sleep hooks and owned user.slice freeze around image write.

Only the installed Omarchy hook inventory is supported. Unknown/changed hooks
fail before power. All host commands are fixed; synthetic roots require an
injected runner. This module never writes power or issues product authority.
"""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import signal

HOOKS = {
  "keyboard-backlight": {
    "79215eed4da8036e25cd70ad09276823aad92d386a68c69d589d587c93b79c60",
    "f313a81e47401f0d38b8602e5997f52c5286d5e97f74027564ddd515b3d16511",
  },
  "unmount-fuse": {"ab7034106e456e93dfb01c6948706c0bfcf0f19e6c9b4c2335b5fb1b3e7ec177"},
}
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C", "SYSTEMD_SLEEP_ACTION": "hibernate"}


def inventory(root):
  paths = []
  for relative in ("usr/lib/systemd/system-sleep", "etc/systemd/system-sleep"):
    directory = Path(root) / relative
    if not directory.exists() and not directory.is_symlink(): continue
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
      raise ValueError("Root-owned sleep hook directory required")
    for hook in sorted(directory.iterdir()):
      info = hook.lstat()
      if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise ValueError("Root-owned regular sleep hook required")
      if hook.name not in HOOKS or info.st_size > 16384 or hashlib.sha256(hook.read_bytes()).hexdigest() not in HOOKS[hook.name]:
        raise ValueError("Unreviewed system-sleep hook")
      if not info.st_mode & 0o111: raise ValueError("Reviewed sleep hook is not executable")
      paths.append(hook)
  if {path.name for path in paths} != set(HOOKS) or len(paths) != len(HOOKS):
    raise ValueError("Exact reviewed system-sleep inventory required")
  return paths


def _run(argv):
  # No captured pipe: the reviewed post hook intentionally backgrounds gvfs
  # restart until after thaw. Waiting for inherited pipes would break that.
  process = subprocess.Popen(argv, env=ENV, start_new_session=True)
  try:
    status = process.wait(timeout=20)
  except BaseException:
    try: os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError: pass
    process.wait()
    raise
  if status: raise subprocess.CalledProcessError(status, argv)


@contextmanager
def window(root, *, runner=None, hook_inventory=None):
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root:
    raise ValueError("Canonical absolute desktop sleep root required")
  if root == Path("/"):
    if os.geteuid() != 0 or runner is not None or hook_inventory is not None:
      raise ValueError("Fixed root desktop sleep operations required")
    runner = _run
  elif runner is None: raise ValueError("Synthetic desktop sleep requires injected operations")
  hooks = inventory(root) if hook_inventory is None else hook_inventory(root)
  def property_value(unit, name):
    # stdout is needed only for the fixed property query, never hook children.
    argv = ["/usr/bin/systemctl", "show", unit, "--property=" + name, "--value"]
    if root == Path("/"):
      return subprocess.run(argv, check=True, capture_output=True, text=True, env=ENV, timeout=5).stdout.strip()
    return runner(argv).stdout.strip()
  def state(): return property_value("user.slice", "FreezerState")
  def reject_managed_homes():
    # Vendor systemd-sleep calls LockAllHomes. This exact-host path supports
    # no homed-managed homes and never starts that subsystem.
    if property_value("systemd-homed.service", "ActiveState") != "inactive":
      raise ValueError("Active systemd-homed is outside desktop sleep compatibility")
    homes = root / "var/lib/systemd/home"
    if homes.exists() or homes.is_symlink():
      info = homes.lstat()
      if not stat.S_ISDIR(info.st_mode) or any(homes.iterdir()):
        raise ValueError("Managed home state is outside desktop sleep compatibility")
  reject_managed_homes()
  if state() != "running": raise ValueError("Cannot own an already frozen user.slice")
  owned = False
  pre_attempted = False
  try:
    # Set ownership before the request: a timeout may still have frozen it.
    owned = True
    runner(["/usr/bin/systemctl", "freeze", "user.slice"])
    if state() != "frozen": raise ValueError("user.slice did not freeze")
    pre_attempted = True
    with ThreadPoolExecutor(max_workers=len(hooks)) as pool:
      for result in pool.map(lambda hook: runner([str(hook), "pre", "hibernate"]), hooks): pass
    reject_managed_homes()
    # Caller retains this context through raw capture, then closes it during
    # workflow cleanup so a post/thaw failure cannot hide return observations.
    yield
  finally:
    try:
      if pre_attempted:
        # Preserve vendor order: post hooks run before thaw. The reviewed FUSE
        # hook's background restart continues after thaw, as in systemd-sleep.
        with ThreadPoolExecutor(max_workers=len(hooks)) as pool:
          for result in pool.map(lambda hook: runner([str(hook), "post", "hibernate"]), hooks): pass
    finally:
      if owned:
        runner(["/usr/bin/systemctl", "thaw", "user.slice"])
        if state() != "running": raise ValueError("user.slice did not thaw")
