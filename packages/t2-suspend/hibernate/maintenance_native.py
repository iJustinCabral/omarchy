"""Reviewed native bootstrap/origin proof; maintenance execution stays DISABLED.

No sibling imports precede self/bootstrap byte pins and whole private inventory
verification. The fixed owner must be a child of the exact block inhibitor,
one/two real sudo nodes and the retained initiating client. sudo's real UID is
the user while effective/saved/fs UIDs are root; sudo PTYs may change session
and terminal, so session equality or SUDO_* environment is NOT authentication.

Origin.bind_peer binds an actual handoff kernel peer to that same initiating
ancestor instance, not another process with matching UID/executable/arguments.
Public-client installation/review, registered active-user/session authorization,
TTY/password behavior, descendant draining and veto-durability retention still
require integration. The entry NEVER creates sockets/markers, transitions boot
policy, launches phases or admits packages, even after every proof succeeds.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
from types import SimpleNamespace


sys.dont_write_bytecode = True
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
RUNTIME = STATE / "runtime"
SCRIPT = RUNTIME / "packages/t2-suspend/hibernate/maintenance_native.py"
CLIENT = Path("/usr/lib/omarchy/t2-hibernate-maintenance-client.py")
PYTHON = Path("/usr/bin/python3")
WHO, WHY = "omarchy-t2-package-maintenance", "reviewed-package-maintenance"
MAX_BYTES = 2 * 1024 * 1024


def _owner_command(): return (str(PYTHON), "-I", "-B", str(SCRIPT))


def _inhibit_command():
  return ("/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block", "--who=" + WHO,
          "--why=" + WHY, "--no-ask-password", *_owner_command())


def _sudo_command(): return ("/usr/bin/sudo", "-n", "--", *_inhibit_command())


def _metadata(info):
  return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
          info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _private(path):
  named = path.lstat()
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= MAX_BYTES or _metadata(info) != _metadata(named):
      raise ValueError("Stable bounded root-private review/code required")
    raw = os.read(fd, MAX_BYTES + 1)
    if len(raw) != info.st_size or _metadata(os.fstat(fd)) != _metadata(info) or _metadata(path.lstat()) != _metadata(info):
      raise ValueError("Reviewed bytes changed or were short")
    return raw
  finally: os.close(fd)


def _pairs(items):
  value = {}
  for key, item in items:
    if key in value: raise ValueError("Duplicate native review field")
    value[key] = item
  return value


def _review(raw):
  value = json.loads(raw, object_pairs_hook=_pairs)
  if type(value) is not dict or set(value) != {"protocol", "approved", "reviewed_commit", "files"} or value["protocol"] != "omarchy-t2-product-runtime-snapshot-v1" or value["approved"] is not True or type(value["reviewed_commit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", value["reviewed_commit"]) or type(value["files"]) is not dict:
    raise ValueError("External exact approved runtime inventory required")
  return value


def _load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


def _pin(review, path):
  raw = _private(path)
  if review["files"].get(path.relative_to(RUNTIME).as_posix()) != {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}:
    raise ValueError("Initial native/bootstrap bytes differ from reviewed inventory")


def _binary(path):
  # Support the observed python3 -> python3.14 same-directory single hop only.
  # resolve() alone can hide an intermediate user-controlled alias namespace.
  for current in path.parents:
    info = current.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISDIR(info.st_mode):
      raise ValueError("Root-controlled native binary namespace required")
  named = path.lstat()
  if named.st_uid != 0: raise ValueError("Root-owned native executable required")
  target = path
  if stat.S_ISLNK(named.st_mode):
    link = Path(os.readlink(path))
    target = link if link.is_absolute() else path.parent / link
    if target.parent != path.parent or target.name in (".", ".."):
      raise ValueError("Only same-directory single-hop binary links supported")
  info = target.lstat()
  if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
    raise ValueError("Resolved native executable must be root-controlled regular")
  if _metadata(path.lstat()) != _metadata(named) or _metadata(target.lstat()) != _metadata(info):
    raise ValueError("Native binary selection changed")
  return str(target)


def _installed():
  if os.getresuid() != (0,) * 3 or not sys.flags.isolated or Path(__file__).absolute() != SCRIPT:
    raise ValueError("Fixed root-private isolated native entry required")
  for path in (SCRIPT, *SCRIPT.parents):
    info = path.lstat()
    if info.st_uid != 0 or info.st_mode & 0o022 or path.is_symlink() or (path != SCRIPT and not stat.S_ISDIR(info.st_mode)):
      raise ValueError("Root-owned nonsymlink native ancestry required")
  for path in (STATE, RUNTIME, *RUNTIME.rglob("*")):
    info = path.lstat()
    if info.st_uid != 0 or path.is_symlink() or stat.S_IMODE(info.st_mode) != (0o700 if stat.S_ISDIR(info.st_mode) else 0o600) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
      raise ValueError("Whole runtime must be root-private before imports")
  review = _review(_private(STATE / "runtime-deployment-review.json"))
  bootstrap = SCRIPT.with_name("runtime_deployment.py")
  _pin(review, SCRIPT)
  _pin(review, bootstrap)
  # The one pre-inventory import is the byte-pinned stdlib-only verifier.
  deployment = _load("maintenance_reviewed_bootstrap", bootstrap)
  deployment._verify_tree(RUNTIME, review["files"])
  _pin(review, SCRIPT)
  for binary in (PYTHON, Path("/usr/bin/systemd-inhibit"), Path("/usr/bin/sudo")): _binary(binary)
  peer = _load("maintenance_reviewed_peer", SCRIPT.with_name("maintenance_peer.py"))
  power = _load("maintenance_private_power", SCRIPT.with_name("boot_policy_native.py"))
  if (power.WHO, power.WHY) != ("omarchy-t2-source-default", "reviewed-boot-policy-transition"):
    raise ValueError("Unexpected reviewed power context")
  # This newly loaded private module instance serves ONLY power queries here.
  # SCRIPT and parent/review methods remain unchanged and are never called;
  # other adapters/modules are not rebound. Context is fixed, assigned once.
  power.WHO, power.WHY = WHO, WHY
  handoff = _load("maintenance_reviewed_handoff", SCRIPT.with_name("maintenance_handoff.py"))
  return SimpleNamespace(peer=peer, power=power, handoff=handoff, review=review)


def _topology(rows, owner_pid):
  """Pure bounded shape validation; live Origin additionally pins/rechecks it."""
  if len(rows) not in (4, 5) or rows[0]["pid"] != owner_pid or len({row["pid"] for row in rows}) != len(rows):
    raise ValueError("Exact owner/inhibitor/one-or-two-sudo/client chain required")
  for child, parent in zip(rows, rows[1:]):
    if child["ppid"] != parent["pid"]: raise ValueError("Broken initiating ancestry")
  python = str(PYTHON.resolve())
  if rows[0]["uids"] != (0,) * 4 or rows[0]["exe"] != python or rows[0]["argv"] != _owner_command():
    raise ValueError("Exact isolated root owner required")
  if rows[1]["uids"] != (0,) * 4 or rows[1]["exe"] != "/usr/bin/systemd-inhibit" or rows[1]["argv"] != _inhibit_command():
    raise ValueError("Exact root block inhibitor parent required")
  client = rows[-1]
  uid = client["uids"][0]
  if type(uid) is not int or uid <= 0 or client["uids"] != (uid,) * 4 or client["exe"] != python or client["argv"] not in ((str(PYTHON), "-I", "-B", str(CLIENT), "run"), (str(PYTHON), "-I", "-B", str(CLIENT), "run", "-y")):
    raise ValueError("Fixed retained nonroot initiating client required")
  for sudo in rows[2:-1]:
    if sudo["uids"] != (uid, 0, 0, 0) or sudo["exe"] != "/usr/bin/sudo" or sudo["argv"] != _sudo_command():
      raise ValueError("Exact mixed-UID sudo main/monitor required")
  try: account = pwd.getpwuid(uid)
  except KeyError: raise ValueError("Actual passwd initiating account required") from None
  if account.pw_gid <= 0: raise ValueError("Nonroot initiating account group required")
  return account


class Origin:
  """One root owner process's pinned ancestry/lifetime; no authorization verdict."""
  def __init__(self, reviewed):
    self.reviewed, self.owner, self.active, self.pins = reviewed, os.getpid(), True, []
    try:
      rows, pid = [], self.owner
      for _ in range(5):
        row = reviewed.peer._identity(pid)
        rows.append(row)
        if len(rows) >= 4 and row["uids"] == (row["uids"][0],) * 4 and row["uids"][0] > 0: break
        pid = row["ppid"]
        if pid <= 1: raise ValueError("Retained initiating client ancestry unavailable")
      self.account = _topology(rows, self.owner)
      self.rows, self.client = tuple(rows), rows[-1]
      for row in self.rows:
        fd = os.pidfd_open(row["pid"])
        self.pins.append(fd)
        os.set_inheritable(fd, False)
        if reviewed.peer._pidfd_pid(fd) != row["pid"]: raise ValueError("Ancestry pidfd instance differs")
      self._processes()
      reviewed.power._power_idle(rows[1]["pid"])
      self._processes()
    except BaseException:
      self.close()
      raise

  def _processes(self):
    if not self.active: raise ValueError("Native origin scope expired")
    if os.getpid() != self.owner: raise ValueError("Native origin belongs to another owner")
    for row, fd in zip(self.rows, self.pins):
      self.reviewed.peer._alive(fd)
      if self.reviewed.peer._pidfd_pid(fd) != row["pid"] or self.reviewed.peer._identity(row["pid"]) != row:
        raise ValueError("Original native ancestry exited/changed/reparented")
      self.reviewed.peer._alive(fd)

  def check(self):
    self._processes()
    self.reviewed.power._power_idle(self.rows[1]["pid"])
    self._processes()

  def bind_peer(self, peer):
    self.check()
    if type(peer) not in (self.reviewed.peer.Peer, self.reviewed.handoff.P.Peer):
      raise ValueError("Actual reviewed handoff kernel peer required")
    expected = {"uid": self.client["uids"][0], "exe": self.client["exe"], "argv": self.client["argv"]}
    observed = peer.require_identity(**expected)
    if peer.pid != self.client["pid"] or peer.gid != self.account.pw_gid or self.reviewed.peer._pidfd_pid(peer.fd) != self.client["pid"] or observed != self.client:
      raise ValueError("Handoff peer is not the pinned initiating ancestor")
    self.check()
    return observed

  def close(self):
    self.active = False  # expiry precedes FD closure/reuse
    while self.pins: os.close(self.pins.pop())

  def __enter__(self): return self
  def __exit__(self, *args): self.close()


def native():
  reviewed = _installed()
  with Origin(reviewed) as origin:
    origin.check()
    raise ValueError("Native maintenance disabled pending descendant drain, durable veto retention and reviewed client/session admission")


def main(argv=None):
  parser = argparse.ArgumentParser(description="Reviewed native origin proof only; maintenance execution unavailable")
  parser.parse_args(argv)
  native()
  return 1


if __name__ == "__main__": raise SystemExit(main())
