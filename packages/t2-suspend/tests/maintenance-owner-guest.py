"""Diskless guest-only own-inhibitor/stop-latch lifetime proof.

Uses exact public source bytes at their fixed guest installed locations. This
does not call native(), mutate boot policy, run ALPM, or prove a production
owner's safe settlement. The small root-private veto and two flocks are guest
simulation only. The external VM timeout bounds a failed retained worker.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time


BASE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate")
READY = Path("/run/maintenance-owner-ready.json")
GO = Path("/run/maintenance-owner-go")
RESULT = Path("/run/maintenance-owner-result.json")
WORKER_ARGV = ("/usr/bin/python3", "-I", "-B", "/maintenance-owner-test.py", "worker")


def guest_gate():
  if (os.getresuid() != (0, 0, 0) or not sys.flags.isolated or
      Path("/etc/os-release").read_bytes() != b"ID=arch\nNAME=Disposable-logind-test\n"):
    raise ValueError("Exact isolated disposable root guest required before helper imports")


def load(name):
  spec = importlib.util.spec_from_file_location("owner_guest_" + name, BASE / (name + ".py"))
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def modules():
  inhibitor, power, peer = (load(name) for name in
    ("maintenance_inhibitor", "boot_policy_native", "maintenance_peer"))
  # Private query-only instance; never modifies a separately loaded adapter.
  power.WHO, power.WHY = inhibitor.WHO, inhibitor.WHY
  return inhibitor, power, peer


def command(inhibitor):
  return ("/usr/bin/systemd-inhibit", "--what=sleep:shutdown", "--mode=block",
    "--who=" + inhibitor.WHO, "--why=" + inhibitor.WHY, *WORKER_ARGV)


def records(power):
  values = power._bus("call", power.LOGIN, "ListInhibitors")
  if len(values) < 2 or values[0] != "a(ssssuu)" or not values[1].isdigit():
    raise RuntimeError("Malformed guest inhibitor inventory")
  count = int(values[1])
  if len(values) != 2 + 6 * count:
    raise RuntimeError("Truncated guest inhibitor inventory")
  return [values[index:index + 6] for index in range(2, len(values), 6)]


def owned(power, pid):
  return [row for row in records(power) if row[0] in ("sleep:shutdown", "shutdown:sleep")
    and row[1:] == [power.WHO, power.WHY, "block", "0", str(pid)]]


def wait_for(test, description, timeout=5):
  deadline = time.monotonic() + timeout
  while not test():
    if time.monotonic() >= deadline:
      raise RuntimeError("Bounded guest wait failed: " + description)
    time.sleep(0.02)


def write_report(path, value):
  raw = json.dumps(value, sort_keys=True).encode() + b"\n"
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  try:
    if os.write(fd, raw) != len(raw): raise RuntimeError("Short guest report")
    os.fsync(fd)
  finally: os.close(fd)


def held(fd, path):
  info = os.fstat(fd)
  named = path.lstat()
  if (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
    raise RuntimeError("Guest lock identity changed")
  probe = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    try: fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: pass
    else: raise RuntimeError("Guest original flock no longer held")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
  finally: os.close(probe)


def worker():
  guest_gate()
  inhibitor, power, peer = modules()
  parent = os.getppid()
  parent_identity = peer._identity(parent)
  if (parent_identity["argv"] != command(inhibitor) or
      parent_identity["exe"] != "/usr/bin/systemd-inhibit" or
      parent_identity["uids"] != (0, 0, 0, 0)):
    raise RuntimeError("Actual fixed guest inhibitor parent required")
  parent_fd = os.pidfd_open(parent)
  if peer._pidfd_pid(parent_fd) != parent or peer._identity(parent) != parent_identity:
    raise RuntimeError("Guest parent instance changed before pin")
  power._power_idle(parent)
  latch = inhibitor.StopLatch().arm()
  owner = inhibitor.acquire(power)
  events = []
  paths = [Path("/run/maintenance-owner-physical.lock"), Path("/run/maintenance-owner-update.lock")]
  locks = []
  for path in paths:
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    locks.append(fd)
  if len(owned(power, parent)) != 1 or len(owned(power, os.getpid())) != 1:
    raise RuntimeError("Both distinct real block records required before parent loss")
  write_report(READY, {"worker": os.getpid(), "parent": parent,
    "starttime": peer._identity(os.getpid())["starttime"], "owner_fd": owner.fd})
  wait_for(GO.exists, "controller pinned worker")
  for number in inhibitor.STOP_SIGNALS:
    os.kill(os.getpid(), number)
  if set(latch.signals) != set(inhibitor.STOP_SIGNALS):
    raise RuntimeError("Actual TERM/HUP/INT were not latched")
  try: latch.check()
  except inhibitor.StopRequested: events.append("new-grants-refused")
  else: raise RuntimeError("Latched stop permitted a new grant")
  for fd, path in zip(locks, paths): held(fd, path)
  owner.check()
  events.append("signals-retained-own-inhibitor-and-flocks")
  if peer._identity(parent) != parent_identity: raise RuntimeError("Pinned parent changed")
  signal.pidfd_send_signal(parent_fd, signal.SIGTERM)
  wait_for(lambda: bool(select.select([parent_fd], [], [], 0)[0]), "original parent death")
  wait_for(lambda: not owned(power, parent), "parent inhibitor release")
  if len(owned(power, os.getpid())) != 1:
    raise RuntimeError("Own inhibitor disappeared with original parent")
  owner.check()
  for fd, path in zip(locks, paths): held(fd, path)
  events.append("parent-dead-own-record-and-flocks-retained")
  # Guest-only simulated settlement: no descendant or package operation.
  time.sleep(0.05)
  veto = Path("/run/maintenance-owner-veto")
  write_report(veto, {"protocol": "guest-only-settled-veto", "worker": os.getpid()})
  directory = os.open(veto.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
  try: os.fsync(directory)
  finally: os.close(directory)
  if json.loads(veto.read_bytes())["worker"] != os.getpid():
    raise RuntimeError("Guest veto readback failed")
  owner.check()
  for fd, path in zip(locks, paths): held(fd, path)
  events.append("simulated-phase-settled-veto-durable")
  owner.close()
  wait_for(lambda: not owned(power, os.getpid()), "own explicit FD release")
  latch.safe_exit()
  for fd in locks: os.close(fd)
  os.close(parent_fd)
  events.append("explicit-safe-release")
  write_report(RESULT, {"events": events, "signals": list(latch.signals),
    "worker": os.getpid(), "parent": parent, "remaining": records(power)})


def main():
  guest_gate()
  inhibitor, power, peer = modules()
  if records(power): raise RuntimeError("Guest inventory must initially be empty")
  version = subprocess.run(["/usr/bin/systemd-inhibit", "--version"], check=True,
    capture_output=True, text=True, timeout=2, env=power.ENV).stdout.splitlines()[0]
  print("MAINTENANCE_OWNER_SYSTEMD " + version, flush=True)
  parent = subprocess.Popen(command(inhibitor), env=power.ENV)
  child_fd = None
  try:
    wait_for(lambda: READY.exists() or parent.poll() is not None, "owner readiness", timeout=10)
    if not READY.exists(): raise RuntimeError("Worker failed before own-FD readiness")
    ready = json.loads(READY.read_bytes())
    if ready["parent"] != parent.pid: raise RuntimeError("Wrong original wrapper instance")
    identity = peer._identity(ready["worker"])
    if (identity["argv"] != WORKER_ARGV or identity["uids"] != (0, 0, 0, 0) or
        identity["starttime"] != ready["starttime"] or identity["ppid"] != parent.pid):
      raise RuntimeError("Wrong ready worker process instance")
    child_fd = os.pidfd_open(ready["worker"])
    if peer._pidfd_pid(child_fd) != ready["worker"] or peer._identity(ready["worker"]) != identity:
      raise RuntimeError("Ready worker changed before controller pin")
    GO.touch(mode=0o600)
    wait_for(lambda: bool(select.select([child_fd], [], [], 0)[0]), "owner completion", timeout=15)
    parent.wait(timeout=3)
    if parent.returncode == 0: raise RuntimeError("Original parent TERM did not cause failure exit")
    if not RESULT.exists(): raise RuntimeError("Worker died without explicit safe-release result")
    result = json.loads(RESULT.read_bytes())
    expected = ["new-grants-refused", "signals-retained-own-inhibitor-and-flocks",
      "parent-dead-own-record-and-flocks-retained", "simulated-phase-settled-veto-durable",
      "explicit-safe-release"]
    if result["events"] != expected or result["remaining"] or records(power):
      raise RuntimeError("Owner lifetime/release evidence incomplete")
    print("MAINTENANCE_OWNER_RESULT " + json.dumps(result, sort_keys=True), flush=True)
    print("MAINTENANCE_OWNER_VM_PASS", flush=True)
  finally:
    if child_fd is not None: os.close(child_fd)
    if parent.poll() is None:
      parent.kill()
      parent.wait(timeout=3)


if __name__ == "__main__":
  if sys.argv[1:] == ["worker"]: worker()
  elif not sys.argv[1:]: main()
  else: raise ValueError("Fixed guest controller/worker argv required")
