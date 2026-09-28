"""Real guest sudo/inhibitor ancestry trace, NOT native maintenance admission.

Both cases use guest-only NOPASSWD and pam_permit, so this does not prove
password authentication, sudo timestamp validation or a registered logind
login session. activation is only the fixed inhibitor command's guest stub
label: native(), boot transitions and package operations never execute.
"""
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pty
import select
import socket
import subprocess
import sys
import termios
import time


BASE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate")
EVIDENCE = Path("/run/maintenance-entry-evidence")
CASE = Path("/run/maintenance-entry-case")
RUNTIME = Path("/run/user/1000")
LOCK = RUNTIME / "omarchy-update.lock"
ENDPOINT = Path("/run/omarchy-t2-maintenance/handoff.sock")


def require(condition, message):
  if not condition: raise RuntimeError(message)


def load(name, path):
  spec = importlib.util.spec_from_file_location(name, path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def modules():
  return load("entry_native", "/native-adapter.py"), load("entry_handoff", BASE / "maintenance_handoff.py")


def process(pid):
  base = Path("/proc") / str(pid)
  fields = (base / "stat").read_text().rsplit(") ", 1)[1].split()
  status = {}
  for line in (base / "status").read_text().splitlines():
    key, _, value = line.partition(":")
    if key in ("Uid", "Gid", "Groups"): status[key] = [int(item) for item in value.split()]
  return {"pid": pid, "ppid": int(fields[1]), "pgrp": int(fields[2]), "sid": int(fields[3]),
          "tty_nr": int(fields[4]), "starttime": int(fields[19]), "uids": status["Uid"],
          "gids": status["Gid"], "groups": status["Groups"], "exe": os.readlink(base / "exe"),
          "argv": [value.decode() for value in (base / "cmdline").read_bytes().split(b"\0")[:-1]]}


def ancestry():
  rows, pid = [], os.getpid()
  for _ in range(16):
    value = process(pid)
    rows.append(value)
    if value["uids"] == [1000] * 4: break
    require(value["ppid"] > 1 and value["ppid"] != pid, "Owner has no retained initiating client ancestor")
    pid = value["ppid"]
  else: raise RuntimeError("Guest ancestry exceeded bound")
  for value in rows:
    require(process(value["pid"]) == value, "Held ancestry changed during capture")
  return rows


def fd_links(pid):
  result = {}
  for path in (Path("/proc") / str(pid) / "fd").iterdir():
    try: result[path.name] = os.readlink(path)
    except FileNotFoundError: pass
  return result


def busy():
  fd = os.open(LOCK, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Original client's update lock was not held")
  finally: os.close(fd)


def owner():
  require(os.getresuid() == (0,) * 3, "Guest root owner required")
  native, handoff = modules()
  case = CASE.read_text()
  require(case in ("use-pty", "no-pty"), "Exact guest trace case required")
  ready = Path("/run/maintenance-entry-" + case + ".ready")
  with native._exclusion("activation", ongoing_power=True) as guard:
    chain = ancestry()
    require(chain[0]["uids"] == [0] * 4 and chain[1]["uids"] == [0] * 4 and chain[1]["exe"] == "/usr/bin/systemd-inhibit", "Real root inhibitor parent required")
    require(chain[1]["argv"] == list(native._inhibit_command("activation")), "Actual inhibitor command differs from fixed guest stub")
    require(len(chain) >= 4 and all(value["exe"] == "/usr/bin/sudo" for value in chain[2:-1]), "Actual sudo monitor/main ancestry required")
    client = chain[-1]
    expected = {"uid": 1000, "exe": str(Path("/usr/bin/python3").resolve()),
                "argv": ["/usr/bin/python3", "-I", "-B", "/maintenance-entry-test.py", "client", case]}
    require(client["exe"] == expected["exe"] and client["argv"] == expected["argv"], "Actual retained user client differs")
    pins = [os.pidfd_open(value["pid"]) for value in chain]
    try:
      with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(ENDPOINT))
        os.chmod(ENDPOINT, 0o666)
        listener.listen(1)
        listener.settimeout(5)
        ready.touch()
        with listener.accept()[0] as stream, handoff.receive_lock(stream, sender_identity=expected, runtime_directory=RUNTIME, timeout=3.0) as receipt:
          require(receipt.check()["pid"] == client["pid"], "Handoff sender is not the actual initiating ancestor")
          require(not os.get_inheritable(receipt.fd) and os.lseek(receipt.fd, 0, os.SEEK_CUR) == 17, "Original writable CLOEXEC lock OFD required")
          os.lseek(receipt.fd, 71, os.SEEK_SET)
          busy()
          guard()
          for value in chain: require(process(value["pid"]) == value, "Ancestry changed after authenticated handoff")
          rows = [{**value, "fd_links": fd_links(value["pid"])} for value in chain]
          inventory = native._bus("call", native.LOGIN, "ListInhibitors")
          payload = {"case": case, "chain": rows, "inhibitors": inventory, "lock_fd": receipt.fd,
                     "shared_offset": 71, "root_pidfd_pids": [handoff.P._pidfd_pid(fd) for fd in pins],
                     "sudo_environment_diagnostic_only": {key: os.environ.get(key) for key in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND")},
                     "scope": "guest-only NOPASSWD/PAM topology; no native activation, admission or registered login session"}
          output = EVIDENCE / (case + ".json")
          temporary = EVIDENCE / (case + ".new")
          temporary.write_text(json.dumps(payload, sort_keys=True))
          temporary.chmod(0o600)
          temporary.replace(output)
          deadline = time.monotonic() + 12
          while not (EVIDENCE / (case + ".release")).exists():
            require(time.monotonic() < deadline, "Guest trace release timed out")
            require(not select.select(pins, [], [], 0)[0], "Actual held sudo/client/inhibitor ancestry exited")
            receipt.check()
            guard()
            time.sleep(0.05)
          receipt.check()
          guard()
    finally:
      for fd in pins: os.close(fd)
      if ENDPOINT.exists(): ENDPOINT.unlink()
      if ready.exists(): ready.unlink()
  print("MAINTENANCE_ENTRY_OWNER_DONE " + case, flush=True)


def client(case):
  require(os.getresuid() == (1000,) * 3 and os.getresgid() == (1000,) * 3, "Actual nonroot guest client required")
  fcntl.ioctl(0, termios.TIOCSCTTY, 0)
  require(os.isatty(0) and os.getsid(0) == os.getpid(), "Initiating client must own an actual terminal session")
  native, handoff = modules()
  fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  privileged = None
  try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.lseek(fd, 17, os.SEEK_SET)
    # The original lock stays here; sudo and systemd-inhibit receive no copy.
    privileged = subprocess.Popen(["/usr/bin/sudo", "-n", "--", *native._inhibit_command("activation")], close_fds=True)
    deadline = time.monotonic() + 8
    while not Path("/run/maintenance-entry-" + case + ".ready").exists():
      require(time.monotonic() < deadline and privileged.poll() is None, "Actual sudo/inhibitor did not establish the guest owner")
      time.sleep(0.02)
    reply = handoff.send_native_lock(fd, timeout=3.0)
    require(reply["accepted"] is True, "Root owner refused original-client descriptor")
    deadline = time.monotonic() + 3
    while os.lseek(fd, 0, os.SEEK_CUR) != 71:
      require(time.monotonic() < deadline, "Root did not share the original client's OFD")
      time.sleep(0.02)
    busy()
    result = privileged.wait(timeout=15)
    require(result == 0, "Actual sudo/inhibitor/root-stub exit failed: " + str(result))
    busy()
    (RUNTIME / (case + ".client.json")).write_text(json.dumps({"pid": os.getpid(), "uids": list(os.getresuid()),
      "sudo_status": result, "shared_offset": os.lseek(fd, 0, os.SEEK_CUR), "original_lock_survived_owner_exit": True}))
    print("MAINTENANCE_ENTRY_CLIENT_DONE " + case, flush=True)
  finally:
    if privileged is not None and privileged.poll() is None:
      privileged.terminate()
      try: privileged.wait(timeout=1)
      except subprocess.TimeoutExpired:
        privileged.kill()
        privileged.wait(timeout=1)
    os.close(fd)


def sudoers(native, case):
  def escape(value):
    for char in ("\\", ",", ":", "="): value = value.replace(char, "\\" + char)
    return value
  command = " ".join(escape(value) for value in native._inhibit_command("activation"))
  path = Path("/etc/sudoers")
  path.write_text("Defaults " + ("use_pty" if case == "use-pty" else "!use_pty") + "\nworker ALL=(root) NOPASSWD: " + command + "\n")
  path.chmod(0o440)


def drain(master, collected):
  if select.select([master], [], [], 0)[0]:
    try: collected.extend(os.read(master, 16384))
    except OSError as error:
      if error.errno != errno.EIO: raise


def main():
  require(os.getresuid() == (0,) * 3, "Dedicated guest root controller required")
  native, handoff = modules()
  EVIDENCE.mkdir(mode=0o700)
  RUNTIME.parent.mkdir(mode=0o755, exist_ok=True)
  RUNTIME.mkdir(mode=0o700)
  os.chown(RUNTIME, 1000, 1000)
  ENDPOINT.parent.mkdir(mode=0o755)
  print("MAINTENANCE_ENTRY_SCOPE actual guest sudo/PTY/inhibitor/client topology; NOPASSWD/PAM, no password timestamp or native admission", flush=True)
  for case in ("use-pty", "no-pty"):
    sudoers(native, case)
    CASE.write_text(case)
    CASE.chmod(0o600)
    master, slave = pty.openpty()
    os.fchown(slave, 1000, 1000)
    os.fchmod(slave, 0o600)
    collected, worker = bytearray(), None
    try:
      argv = ["/usr/bin/python3", "-I", "-B", "/maintenance-entry-test.py", "client", case]
      worker = subprocess.Popen(argv, user=1000, group=1000, extra_groups=[1000, 1001], start_new_session=True,
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/home/worker", "USER": "worker", "LOGNAME": "worker", "TERM": "xterm"})
      os.close(slave)
      slave = None
      output = EVIDENCE / (case + ".json")
      deadline = time.monotonic() + 12
      while not output.exists():
        drain(master, collected)
        require(time.monotonic() < deadline and worker.poll() is None, "Actual entry trace did not become ready: " + collected.decode(errors="replace"))
        time.sleep(0.02)
      value = json.loads(output.read_text())
      chain = value["chain"]
      require(chain[-1]["pid"] == worker.pid and chain[-1]["ppid"] == os.getpid() and chain[-1]["sid"] == worker.pid and chain[-1]["tty_nr"] != 0, "Trace does not bind the retained direct initiating terminal client")
      require(value["root_pidfd_pids"] == [row["pid"] for row in chain], "Captured ancestry PID instances differ")
      if case == "use-pty":
        require(chain[0]["sid"] != chain[-1]["sid"] and chain[0]["tty_nr"] != chain[-1]["tty_nr"], "sudo use_pty did not create a distinct terminal session")
      else:
        require(chain[0]["sid"] == chain[-1]["sid"] and chain[0]["tty_nr"] == chain[-1]["tty_nr"], "sudo !use_pty unexpectedly changed the terminal session")
      busy()
      native._power_idle(chain[1]["pid"])
      print("MAINTENANCE_ENTRY_TRACE " + json.dumps(value, sort_keys=True), flush=True)
      (EVIDENCE / (case + ".release")).touch()
      deadline = time.monotonic() + 8
      while worker.poll() is None:
        drain(master, collected)
        require(time.monotonic() < deadline, "Actual sudo/client exit timed out")
        time.sleep(0.02)
      drain(master, collected)
      print("MAINTENANCE_ENTRY_TERMINAL " + case + " " + collected.decode(errors="replace"), flush=True)
      require(worker.returncode == 0, "Actual terminal client failed")
      result = json.loads((RUNTIME / (case + ".client.json")).read_text())
      require(result["pid"] == worker.pid and result["uids"] == [1000] * 3 and result["sudo_status"] == 0 and result["shared_offset"] == 71 and result["original_lock_survived_owner_exit"], "Originating user did not retain its original lock and exit status")
      require(native._bus("call", native.LOGIN, "ListInhibitors") == ["a(ssssuu)", "0"], "Real inhibitor FD survived completed sudo/client chain")
      fd = os.open(LOCK, os.O_RDWR | os.O_CLOEXEC)
      try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      finally: os.close(fd)
      LOCK.unlink()
      print("MAINTENANCE_ENTRY_CASE_PASS " + case, flush=True)
    finally:
      if worker is not None and worker.poll() is None:
        (EVIDENCE / (case + ".release")).touch()
        try: worker.wait(timeout=2)
        except subprocess.TimeoutExpired:
          worker.terminate()
          try: worker.wait(timeout=1)
          except subprocess.TimeoutExpired:
            worker.kill()
            worker.wait(timeout=1)
      if slave is not None: os.close(slave)
      os.close(master)
  print("MAINTENANCE_ENTRY_VM_PASS", flush=True)


if __name__ == "__main__":
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated networkless disposable guest required")
  if len(sys.argv) == 3 and sys.argv[1] == "client" and sys.argv[2] in ("use-pty", "no-pty"): client(sys.argv[2])
  elif len(sys.argv) == 1: main()
  else: raise RuntimeError("Fixed guest controller/client invocation required")
