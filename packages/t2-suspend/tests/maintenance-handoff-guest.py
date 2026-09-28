"""Guest-only cross-UID original update-lock transfer; no native admission.

Root creates its own listener; the dropped worker creates each fresh client
and keeps the original descriptor open. Only dedicated disposable VM paths,
accounts and exact repository sources are used. Never run this on the host.
"""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import sys


SOURCE = Path("/var/lib/omarchy/t2-hibernate-product/runtime/packages/t2-suspend/hibernate/maintenance_handoff.py")
ENDPOINT = Path("/run/omarchy-t2-maintenance/handoff.sock")
RUNTIME = Path("/run/user/1000")
LOCK = RUNTIME / "omarchy-update.lock"


def require(condition, message):
  if not condition: raise RuntimeError(message)


def module():
  spec = importlib.util.spec_from_file_location("guest_maintenance_handoff", SOURCE)
  handoff = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(handoff)
  return handoff


def busy():
  fd = os.open(LOCK, os.O_RDWR | os.O_CLOEXEC)
  try:
    try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: return
    raise RuntimeError("Original update-lock exclusion was lost")
  finally: os.close(fd)


def line(process, expected):
  require(bool(select.select([process.stdout], [], [], 3)[0]), "Worker evidence timed out: " + expected)
  observed = process.stdout.readline().decode().strip()
  require(observed == expected, "Worker evidence differs: " + repr(observed))
  print(observed, flush=True)


def command(process, value):
  process.stdin.write(value.encode() + b"\n")
  process.stdin.flush()


def worker(handoff, root_pid):
  require(os.getresuid() == (1000,) * 3 and os.getresgid() == (1000,) * 3 and sorted(os.getgroups()) == [1000, 1001], "Exact nonroot fixture worker required")
  try: os.readlink("/proc/" + str(root_pid) + "/exe")
  except PermissionError: print("MAINTENANCE_HANDOFF_ROOT_EXE_DENIED", flush=True)
  else: raise RuntimeError("Guest did not reproduce cross-UID root executable access denial")
  with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
    stream.settimeout(3)
    stream.connect(str(ENDPOINT))
    try:
      with handoff.P.Peer(stream): pass
    except ValueError as error:
      require(isinstance(error.__cause__, PermissionError), "Strict Peer failed for a reason other than cross-UID process access: " + repr(error))
      print("MAINTENANCE_HANDOFF_STRICT_PEER_REFUSED", flush=True)
    else: raise RuntimeError("Strict Peer unexpectedly observed root executable")
  fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
  try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.lseek(fd, 17, os.SEEK_SET)
    require(sys.stdin.readline().strip() == "bad-namespace", "Expected endpoint namespace negative case")
    try: handoff.send_native_lock(fd, timeout=1.0)
    except ValueError as error:
      require(str(error) == "Fixed root socket with explicit connection permissions required", "Namespace refused for an unexpected reason: " + str(error))
      print("MAINTENANCE_HANDOFF_BAD_NAMESPACE_REFUSED", flush=True)
    else: raise RuntimeError("Native client accepted unsafe fixed endpoint permissions")
    require(sys.stdin.readline().strip() == "start", "Expected safe endpoint continuation")
    for case in ("closed-receipt", "dead-sender"):
      reply = handoff.send_native_lock(fd, timeout=3.0)
      require(reply.get("accepted") is True, "Native helper did not return exact acceptance")
      print("MAINTENANCE_HANDOFF_SENT " + case, flush=True)
      require(sys.stdin.readline().strip() == "check-offset", "Expected root offset check")
      require(os.lseek(fd, 0, os.SEEK_CUR) == 71, "SCM_RIGHTS did not preserve the original open file description")
      busy()
      print("MAINTENANCE_HANDOFF_ORIGINAL_HELD " + case, flush=True)
      require(sys.stdin.readline().strip() == "continue", "Expected root continuation")
      if case == "closed-receipt":
        busy()
        print("MAINTENANCE_HANDOFF_ORIGINAL_SURVIVES_CLOSE", flush=True)
      else:
        print("MAINTENANCE_HANDOFF_WORKER_EXIT", flush=True)
  finally: os.close(fd)


def main(handoff):
  require(os.getresuid() == (0,) * 3 and os.getresgid() == (0,) * 3, "Root proof must run inside the guest")
  user = pwd.getpwnam("worker")
  require((user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell) == (1000, 1000, "/home/worker", "/bin/bash"), "Exact guest-only worker account required")
  RUNTIME.parent.mkdir(mode=0o755, exist_ok=True)
  RUNTIME.mkdir(mode=0o700)
  os.chown(RUNTIME, 1000, 1000)
  ENDPOINT.parent.mkdir(mode=0o755)
  os.chmod(ENDPOINT.parent, 0o755)
  argv = ["/usr/bin/python3", "-I", "-B", "/maintenance-handoff-test.py", "worker", str(os.getpid())]
  identity = {"uid": 1000, "exe": str(Path(argv[0]).resolve()), "argv": argv}
  process, receipt = None, None
  print("MAINTENANCE_HANDOFF_SCOPE cross-UID socket and lock descriptor proof only; no native admission", flush=True)
  with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    # The root process itself creates/listens: SO_PEERCRED must identify this
    # actual endpoint creator, never a child inheriting a root endpoint.
    listener.bind(str(ENDPOINT))
    os.chmod(ENDPOINT, 0o666)
    listener.listen(4)
    listener.settimeout(5)
    process = subprocess.Popen(argv, user=1000, group=1000, extra_groups=[1000, 1001],
                               env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None, bufsize=0)
    try:
      line(process, "MAINTENANCE_HANDOFF_ROOT_EXE_DENIED")
      with listener.accept()[0] as stream:
        stream.settimeout(3)
        require(stream.recv(1) == b"", "Strict Peer refusal must send no protocol or descriptor")
      line(process, "MAINTENANCE_HANDOFF_STRICT_PEER_REFUSED")
      os.chmod(ENDPOINT, 0o600)
      command(process, "bad-namespace")
      line(process, "MAINTENANCE_HANDOFF_BAD_NAMESPACE_REFUSED")
      require(not select.select([listener], [], [], 0)[0], "Unsafe namespace refusal still connected to the listener")
      os.chmod(ENDPOINT, 0o666)
      command(process, "start")
      for case in ("closed-receipt", "dead-sender"):
        with listener.accept()[0] as stream:
          receipt = handoff.receive_lock(stream, sender_identity=identity, runtime_directory=RUNTIME, timeout=3.0)
          line(process, "MAINTENANCE_HANDOFF_SENT " + case)
          observed = receipt.check()
          require(observed["pid"] == process.pid and observed["uids"] == (1000,) * 4, "Receipt did not bind the real nonroot child")
          require(not os.get_inheritable(receipt.fd), "Kernel lock receipt was not CLOEXEC")
          require(os.lseek(receipt.fd, 0, os.SEEK_CUR) == (17 if case == "closed-receipt" else 71), "Received lock offset differs from original")
          os.lseek(receipt.fd, 71, os.SEEK_SET)
          busy()
          command(process, "check-offset")
          line(process, "MAINTENANCE_HANDOFF_ORIGINAL_HELD " + case)
          receipt.check()
          print("MAINTENANCE_HANDOFF_RECEIPT " + json.dumps({"pid": process.pid, "uid": 1000, "cloexec": True, "shared_offset": 71, "case": case}), flush=True)
          if case == "closed-receipt":
            receipt.close()
            try: receipt.check()
            except ValueError: print("MAINTENANCE_HANDOFF_CLOSED_RECEIPT_REFUSED", flush=True)
            else: raise RuntimeError("Closed lock receipt retained authority")
            receipt = None
            busy()
            command(process, "continue")
            line(process, "MAINTENANCE_HANDOFF_ORIGINAL_SURVIVES_CLOSE")
          else:
            command(process, "continue")
            line(process, "MAINTENANCE_HANDOFF_WORKER_EXIT")
            require(process.wait(timeout=3) == 0, "Nonroot worker failed")
            try: receipt.check()
            except ValueError: print("MAINTENANCE_HANDOFF_DEAD_SENDER_REFUSED", flush=True)
            else: raise RuntimeError("Dead sender retained receipt authority")
            busy()
            receipt.close()
            receipt = None
      fd = os.open(LOCK, os.O_RDWR | os.O_CLOEXEC)
      try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      finally: os.close(fd)
      print("MAINTENANCE_HANDOFF_VM_PASS", flush=True)
    finally:
      if receipt is not None: receipt.close()
      if process.returncode is None:
        process.terminate()
        try: process.wait(timeout=1)
        except subprocess.TimeoutExpired:
          process.kill()
          process.wait(timeout=1)
      process.stdin.close()
      process.stdout.close()


if __name__ == "__main__":
  require(Path("/etc/os-release").read_text() == "ID=arch\nNAME=Disposable-logind-test\n", "Dedicated disposable VM required")
  handoff = module()
  if len(sys.argv) == 3 and sys.argv[1] == "worker": worker(handoff, int(sys.argv[2]))
  elif len(sys.argv) == 1: main(handoff)
  else: raise RuntimeError("Fixed guest controller or worker invocation required")
