"""Dedicated networkless guest ALPM ordering, NEVER a host/native update test.

Real pacman uses the guest '/' and a guest-only database. Only the package's
/opt/fixture payload is installed. Hook admission explicitly points to synthetic
F.Transitions evidence, not native update_guard.main or saved-image/header proof.
No kernel, EFI, qualification, public-client or automatic reactivation claim.
"""
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from unittest.mock import patch


BASE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend")
SCRIPT = Path("/maintenance-alpm-test.py")
WORK = Path("/run/maintenance-alpm")
PAYLOAD = Path("/opt/fixture/alpm-payload")
PACKAGE = "maintenance-alpm-fixture"
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


def require(value, message):
  if not value: raise RuntimeError(message)


def load(name, path):
  spec = importlib.util.spec_from_file_location("alpm_guest_" + name, path)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


def power_context():
  inhibitor = load("inhibitor", BASE / "hibernate/maintenance_inhibitor.py")
  power = load("power", BASE / "hibernate/boot_policy_native.py")
  # Isolated guest module, not the global installed activation adapter. Its
  # original read-only predicates verify the actual owner's logind record.
  power.WHO, power.WHY = inhibitor.WHO, inhibitor.WHY
  return inhibitor, power


def busy(path):
  fd = os.open(path, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Owner physical exclusion was not held")
  finally: os.close(fd)


def write(path, raw, mode=0o600):
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
  with os.fdopen(fd, "wb") as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())


def emit(record):
  raw = (json.dumps(record, sort_keys=True) + "\n").encode()
  fd = os.open(WORK / "hook-events.jsonl", os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  with os.fdopen(fd, "ab") as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
  print("MAINTENANCE_ALPM_HOOK " + raw.decode().strip(), flush=True)


def hook(phase):
  state = json.loads((WORK / "case.json").read_bytes())
  root = Path(state["fixture_root"])
  guard = load("hook_guard", BASE / "hibernate/update_guard.py")
  _, power = power_context()
  record = {"case": state["case"], "phase": phase, "pid": os.getpid(),
    "payload_sha256": hashlib.sha256(PAYLOAD.read_bytes()).hexdigest() if PAYLOAD.exists() else None}
  try:
    lock = root / "var/lib/pacman/db.lck"
    info = lock.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1, "Actual ALPM database lock missing")
    busy(root / "var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock")
    power._power_ongoing(state["owner_pid"])
    record.update({"db_lock_exists": True, "db_lock_devino": [info.st_dev, info.st_ino],
      "physical_held": True, "owner_inhibitor_held": True})
    if phase == "pre":
      result = guard.check_inactive_maintenance(root)
      require(result["classification"] == "fixture-inactive-maintenance-verified", "Unexpected fixture classification")
      record["decision"] = result["classification"]
    else:
      require(phase == "post" and PAYLOAD.read_bytes() == b"accepted-v1\n", "Post-hook ran without installed v1 payload")
      record["decision"] = "posttransaction-observed"
    emit(record)
    return 0
  except Exception as error:
    record.update({"decision": "refuse", "error_type": type(error).__name__})
    emit(record)
    return 1


def package(version, payload):
  path = WORK / (PACKAGE + "-" + version + "-x86_64.pkg.tar.gz")
  metadata = ("pkgname = " + PACKAGE + "\npkgbase = " + PACKAGE + "\npkgver = " + version +
    "\npkgdesc = Disposable ALPM fixture only\nbuilddate = 1700000000\npackager = Disposable fixture\nsize = " +
    str(len(payload)) + "\narch = x86_64\nlicense = MIT\n").encode()
  with tarfile.open(path, "w:gz") as archive:
    for name, raw in ((".PKGINFO", metadata), ("opt/fixture/alpm-payload", payload)):
      entry = tarfile.TarInfo(name)
      entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(raw), 0o644, 0, 0, 1700000000
      archive.addfile(entry, io.BytesIO(raw))
  return path


def db_version(root):
  entries = list((root / "var/lib/pacman/local").glob(PACKAGE + "-*/desc"))
  require(len(entries) == 1, "Ambiguous fixture package database")
  raw = entries[0].read_text()
  require("%VERSION%\n1.0-1\n" in raw, "Failed transaction changed installed package version")
  return hashlib.sha256(entries[0].read_bytes()).hexdigest()


def owner():
  F = load("transition_fixture", BASE / "tests/test-hibernate-boot-policy-transition.py")
  G = load("owner_guard", BASE / "hibernate/update_guard.py")
  I, power = power_context()
  require(power._bus("call", power.LOGIN, "ListInhibitors") == ["a(ssssuu)", "0"], "Dedicated guest must start with exactly no inhibitors")
  # Gate is NOT patched: exact installed helper path, root, isolated Python,
  # private600 helper and root-controlled nonsymlink namespace are required.
  block = I.acquire(power)
  original_temporary = tempfile.TemporaryDirectory
  fixture = F.Transitions("test_activation_then_exact_fallback_preserves_all_authority_and_evidence")
  with patch.object(tempfile, "TemporaryDirectory", side_effect=lambda: original_temporary(prefix="maintenance-alpm-", dir="/run")):
    fixture.setUp()
  root, data, T = fixture.root, fixture.f, F.T
  block.check()
  fixture.run_action()
  fixture.run_action("maintenance")
  original = (root / T.MAINTENANCE).read_bytes()
  require(not PAYLOAD.exists(), "Guest payload must start absent")
  WORK.mkdir(mode=0o700)
  hooks = WORK / "hooks"
  hooks.mkdir(mode=0o700)
  cache = WORK / "cache"
  cache.mkdir(mode=0o700)
  for name, phase, when, abort in (("00-fixture-maintenance.hook", "pre", "PreTransaction", "AbortOnFail\n"),
                                  ("90-fixture-result.hook", "post", "PostTransaction", "")):
    raw = ("[Trigger]\nOperation = Install\nOperation = Upgrade\nOperation = Remove\nType = Package\nTarget = " + PACKAGE +
      "\n[Action]\nWhen = " + when + "\nExec = /usr/bin/python3 -I -B " + str(SCRIPT) + " hook " + phase + "\n" + abort).encode()
    write(hooks / name, raw)
  # Root stays actual guest '/': libalpm never chroots into the synthetic root.
  # The real DB lock DOES reside at exactly T.DB_LOCK below that fixture root.
  config = ("[options]\nArchitecture = x86_64\nSigLevel = Never\nLocalFileSigLevel = Never\nDBPath = " + str(root / "var/lib/pacman") +
    "\nCacheDir = " + str(cache) + "\nLogFile = " + str(WORK / "pacman.log") + "\nHookDir = " + str(hooks) + "\n").encode()
  write(WORK / "pacman.conf", config)
  first, second = package("1.0-1", b"accepted-v1\n"), package("2.0-1", b"must-not-install-v2\n")
  events = WORK / "hook-events.jsonl"
  with T._locks(root) as release_db:
    release_db()  # retain physical flock, let ACTUAL pacman own its DB lock
    for case, candidate in (("valid-v1", first), ("forged-v2", second)):
      block.check()
      release_db.check_physical()
      if case == "forged-v2":
        forged = T._encoded({**json.loads(original), "old_policy_sha256": "f" * 64})
        write(root / T.MAINTENANCE, forged)
        T._sync((root / T.MAINTENANCE).parent)
      write(WORK / "case.json", json.dumps({"case": case, "fixture_root": str(root), "owner_pid": os.getpid()}).encode())
      command = ["/usr/bin/pacman", "--config", str(WORK / "pacman.conf"), "--noconfirm", "-U", str(candidate)]
      process = subprocess.Popen(command, env=ENV, close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      output, _ = process.communicate()  # sole reaper; never cancel/kill ALPM
      print(output.decode("utf-8", "replace"), end="", flush=True)
      block.check()
      release_db.check_physical()
      require(not (root / T.DB_LOCK).exists(), "Pacman database lock remained after real exit")
      observed = [json.loads(line) for line in events.read_bytes().splitlines()]
      current = [event for event in observed if event["case"] == case]
      require(current and all(event.get("db_lock_exists") and event.get("physical_held") and event.get("owner_inhibitor_held") for event in current), "Hook exclusion/actual DB proof missing")
      require(PAYLOAD.read_bytes() == b"accepted-v1\n", "Refused transaction altered payload")
      version = db_version(root)
      if case == "valid-v1":
        require(process.returncode == 0 and [event["phase"] for event in current] == ["pre", "post"], "Real accepted ALPM ordering/status failed")
        require(current[0]["payload_sha256"] is None and current[0]["decision"] == "fixture-inactive-maintenance-verified", "Pre-hook did not precede installation")
        require(current[1]["payload_sha256"] == hashlib.sha256(b"accepted-v1\n").hexdigest(), "Post-hook did not follow extraction")
        accepted_version = version
      else:
        require(process.returncode != 0 and [event["phase"] for event in current] == ["pre"] and current[0]["decision"] == "refuse", "AbortOnFail did not stop real upgrade")
        require(version == accepted_version and (root / T.MAINTENANCE).read_bytes() == forged, "Refusal changed DB or forged evidence")
      try: G.check(root)
      except ValueError: pass
      else: raise RuntimeError("Unchanged native-style guard unexpectedly admitted maintenance")
      print("MAINTENANCE_ALPM_CASE " + json.dumps({"case": case, "actual_returncode": process.returncode,
        "payload_sha256": hashlib.sha256(PAYLOAD.read_bytes()).hexdigest(), "package_version": "1.0-1",
        "db_lock_absent_after_wait": True, "native_guard_refused": True}), flush=True)
    # Explicit controlled-test restoration, not a native foreign-marker repair.
    # Preserve forged bytes through refusal assertions, then restore this test's
    # exact known original marker durably BEFORE owner releases its block FD.
    write(root / T.MAINTENANCE, original)
    T._sync((root / T.MAINTENANCE).parent)
    require(G.check_inactive_maintenance(root)["maintenance_intent_sha256"] == hashlib.sha256(original).hexdigest(), "Controlled fixture restoration failed")
    T._veto(root, original, durable=True)
    block.check()
  block.check()
  block.close()  # both real pacman children exited; exact fixture veto durable
  deadline = time.monotonic() + 2
  while True:
    rows = power._bus("call", power.LOGIN, "ListInhibitors")
    if rows == ["a(ssssuu)", "0"]: break
    require(time.monotonic() < deadline, "Owner inhibitor remained after explicit safe close")
    time.sleep(.02)
  print("MAINTENANCE_ALPM_OWNER_RELEASED", flush=True)
  fixture.doCleanups()
  print("MAINTENANCE_ALPM_VM_PASS", flush=True)


def main():
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated disposable VM only")
  require(Path(__file__).absolute() == SCRIPT and os.getresuid() == (0,) * 3 and sys.flags.isolated, "Fixed isolated guest root script only")
  if len(sys.argv) == 3 and sys.argv[1] == "hook" and sys.argv[2] in ("pre", "post"):
    return hook(sys.argv[2])
  require(not sys.argv[1:], "Fixed two ALPM cases only")
  owner()
  return 0


if __name__ == "__main__": raise SystemExit(main())
