"""Fixed root entry for systemd-hibernate.service; no direct desktop admission."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess

OPT_IN = Path("/etc/omarchy/t2-hibernate-product.enabled")
MODEL = Path("/sys/class/dmi/id/product_name")
STOCK = "/usr/lib/systemd/systemd-sleep"
PRODUCT = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/product.py")
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
STATE = Path("var/lib/omarchy/t2-hibernate-product")
PENDING = ("source-default-activation.pending", "source-default-deactivation.pending")


def reject_pending(root=Path("/")):
  """Veto both routes while a cooperating boot-policy transition is incomplete.

  This is admission only, not serialization with an already running writer.
  A future live transition must separately own a real block inhibitor and
  establish inactive sleep units before it changes boot policy.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Canonical pending-transition root required")
  if root == Path("/") and os.geteuid() != 0: raise ValueError("Root pending admission required")
  owner = 0 if root == Path("/") else os.geteuid()
  for name in PENDING:
    path = root / STATE / name
    for parent in path.parents:
      try: info = parent.lstat()
      except FileNotFoundError: continue
      if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, owner) or info.st_mode & 0o022:
        raise ValueError("Owned nonsymlink pending-transition ancestors required")
      if parent == root: break
    try: path.lstat()
    except FileNotFoundError: continue
    raise ValueError("Incomplete source-default transition blocks hibernation")


def opted_in(marker=OPT_IN, model=MODEL, *, query=None):
  """Absent marker is stock; any present but invalid marker refuses fallback."""
  try: info = marker.lstat()
  except FileNotFoundError: return False
  if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644 or info.st_size != 0:
    raise ValueError("Invalid T2 opt-in marker; refusing stock fallback")
  if model.read_text().strip() != "MacBookAir9,1": raise ValueError("T2 opt-in requires exact MacBookAir9,1")
  if query is None:
    raw = subprocess.run(["/usr/bin/lspci", "-nn"], check=True, capture_output=True, text=True, env=ENV, timeout=5).stdout
  else: raw = query()
  if "106b:1801" not in raw and "106b:1802" not in raw: raise ValueError("T2 PCI identity required")
  return True


def main(argv=None):
  if argv is None:
    import sys
    argv = sys.argv[1:]
  if argv: raise ValueError("No sleep-entry arguments permitted")
  if os.geteuid() != 0: raise ValueError("Root systemd sleep entry required")
  reject_pending()
  if not opted_in():
    os.execve(STOCK, [STOCK, "hibernate"], dict(os.environ))
  else:
    # The reviewed runtime is root-private; never import the user workspace.
    for path in (PRODUCT, *PRODUCT.parents[:-1]):
      info = path.lstat()
      if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Root-owned non-writable runtime required")
      if path == PRODUCT:
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
          raise ValueError("Regular non-linked product dispatcher required")
      elif not stat.S_ISDIR(info.st_mode): raise ValueError("Runtime directory required")
    spec = importlib.util.spec_from_file_location("root_product_sleep", PRODUCT)
    product = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(product)
    return product.main(["hibernate", "--desktop"])


if __name__ == "__main__": raise SystemExit(main())
