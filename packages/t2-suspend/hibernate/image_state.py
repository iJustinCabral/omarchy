"""Read-only no-image prerequisite at the exact qualified Btrfs resume page.

The caller must separately own power/physical exclusion and prove reconciled
ledger and absent EFI stages. A normal header alone never permits an update.
The parser is the reviewed runtime copy of the existing Linux 7.2.6 auditor.
"""
import importlib.util
import os
from pathlib import Path
import re
import stat
import subprocess

RUNTIME = Path("/var/lib/omarchy/t2-hibernate-product/runtime")
SOURCE = RUNTIME / "packages/t2-suspend/hibernate/image_state.py"
PARSER = Path(__file__).resolve().parents[1] / "experiments/audit-hibernation-swap-header.py"
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LANG": "C"}
PAGE = 4096


def _query(argv):
  result = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=10, env=ENV)
  if result.returncode or len(result.stdout.encode()) > 4096 or result.stderr and len(result.stderr.encode()) > 4096:
    raise ValueError("Bounded resume topology query failed")
  return result.stdout.strip()


def _alias(root, owner):
  for directory in (root / "dev", root / "dev/mapper"):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
      raise ValueError("Owned nonsymlink mapper directories required")
  alias = root / "dev/mapper/root"
  info = alias.lstat()
  target = os.readlink(alias)
  if not stat.S_ISLNK(info.st_mode) or info.st_uid != owner or not re.fullmatch(r"\.\./dm-[0-9]+", target):
    raise ValueError("Exact root-mapper block alias required")
  return alias, (info.st_dev, info.st_ino, target), root / "dev" / target[3:]


def _stable_alias(alias, identity, target, opened):
  now = alias.lstat()
  if (now.st_dev, now.st_ino, os.readlink(alias)) != identity:
    raise ValueError("Resume mapper alias changed during header read")
  current = target.stat(follow_symlinks=False)
  if stat.S_IFMT(current.st_mode) != stat.S_IFMT(opened.st_mode):
    raise ValueError("Resume block target changed")
  if (current.st_dev, current.st_ino, current.st_rdev) != (opened.st_dev, opened.st_ino, opened.st_rdev):
    raise ValueError("Opened resume target was replaced")


def require_no_image(root, resume, *, query=None, fixture_identity=None):
  """Reject pending/unknown/truncated images without modifying the target.

  `resume` is the reviewed report's exact {device, devnum, offset} object.
  Fixture callbacks are forbidden for live `/`; live callers must import the
  root-private reviewed runtime and hold their own exclusion across this call.
  """
  root = Path(root)
  if not root.is_absolute() or root.resolve() != root or not root.is_dir():
    raise ValueError("Canonical explicit image-check root required")
  if root == Path("/"):
    if os.geteuid() != 0 or query is not None or fixture_identity is not None or Path(__file__).absolute() != SOURCE:
      raise ValueError("Only fixed root-private live image check is allowed")
  elif query is None or fixture_identity is None:
    raise ValueError("Synthetic root requires explicit query and block identity fixture")
  if (type(resume) is not dict or set(resume) != {"device", "devnum", "offset"} or
      resume["device"] != "/dev/mapper/root" or type(resume["devnum"]) is not str or
      not re.fullmatch(r"[0-9]+:[0-9]+", resume["devnum"]) or
      type(resume["offset"]) is not int or not 0 < resume["offset"] <= (2**63 - 1 - PAGE) // PAGE):
    raise ValueError("Exact qualified resume target required")
  query = _query if query is None else query
  expected = tuple(int(part) for part in resume["devnum"].split(":"))
  def topology():
    if (root / "sys/power/resume").read_text().strip() != resume["devnum"] or (root / "sys/power/resume_offset").read_text().strip() != str(resume["offset"]):
      raise ValueError("Active kernel resume target differs")
    if query(("/usr/bin/btrfs", "inspect-internal", "map-swapfile", "-r", "/swap/swapfile")) != str(resume["offset"]):
      raise ValueError("Actual Btrfs swapfile mapping differs")
    if not re.fullmatch(r"/dev/mapper/root(?:\[/[^\]\r\n]*\])? btrfs",
                        query(("/usr/bin/findmnt", "-n", "-o", "SOURCE,FSTYPE", "--target", "/swap/swapfile"))):
      raise ValueError("Swapfile is not on the qualified encrypted Btrfs root")
  topology()
  owner = 0 if root == Path("/") else os.geteuid()
  alias, identity, target = _alias(root, owner)
  fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
  try:
    opened = os.fstat(fd)
    if root == Path("/"):
      if not stat.S_ISBLK(opened.st_mode) or opened.st_uid != 0 or (os.major(opened.st_rdev), os.minor(opened.st_rdev)) != expected:
        raise ValueError("Opened resume block identity differs")
    else:
      if not stat.S_ISREG(opened.st_mode): raise ValueError("Synthetic resume target must be a regular fixture file")
      if fixture_identity(fd) != expected: raise ValueError("Fixture opened resume identity differs")
    _stable_alias(alias, identity, target, opened)
    page = os.pread(fd, PAGE, resume["offset"] * PAGE)
    if len(page) != PAGE: raise ValueError("Truncated resume header page")
    spec = importlib.util.spec_from_file_location("reviewed_swap_header", PARSER)
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    header = parser.parse_header(page)
    # The existing parser also labels legacy SWAP-SPACE normal; this fixed
    # x86-64 generation requires the exact version-1 SWAPSPACE2 page instead.
    if (header["marker"] != "normal-swap-signature" or page[-10:] != b"SWAPSPACE2" or
        page[1024:1028] != b"\x01\0\0\0"):
      raise ValueError("Pending or unknown hibernation image header")
    _stable_alias(alias, identity, target, opened)
    topology()
    return {"classification": "no-image-at-qualified-resume-page", "device": resume["device"],
            "devnum": resume["devnum"], "offset": resume["offset"], "page_sha256": header["page_sha256"]}
  finally: os.close(fd)
