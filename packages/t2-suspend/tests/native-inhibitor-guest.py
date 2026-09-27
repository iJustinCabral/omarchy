"""Guest-only real inhibitor guard proof; never calls native()/transition().

The fixed installed SCRIPT is a stub launcher for worker(), not the installed
native CLI. /native-adapter.py contains the exact repository adapter bytes.
Only its read-only exclusion/identity/power-idle functions execute here.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time


def adapter():
  spec = importlib.util.spec_from_file_location("unchanged_native_adapter", "/native-adapter.py")
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


def worker():
  native = adapter()
  case = Path("/run/native-case").read_text()
  if case == "held":
    with native._exclusion("activation") as guard:
      guard()
      guard()
      print("NATIVE_INHIBITOR_HELD " + str(os.getppid()), flush=True)
      deadline = time.monotonic() + 15
      while not Path("/run/native-release").exists():
        if time.monotonic() > deadline:
          raise RuntimeError("Bounded guest release handshake timed out")
        time.sleep(0.05)
      guard()
    print("NATIVE_INHIBITOR_REPEATED_GUARD_PASS", flush=True)
    return
  try:
    with native._exclusion("activation"):
      raise RuntimeError("Invalid ownership was accepted")
  except ValueError as error:
    expected = "Exact systemd-inhibit parent required" if case == "absent" else "Exact fixed inhibitor command required"
    if str(error) != expected:
      raise RuntimeError("Unexpected ownership rejection: " + str(error)) from error
    print("NATIVE_INHIBITOR_REJECT " + case + " " + str(error), flush=True)


def inhibitors(native):
  records = native._bus("call", native.LOGIN, "ListInhibitors")
  print("NATIVE_INHIBITOR_INVENTORY " + json.dumps(records), flush=True)
  return records


def empty(native):
  deadline = time.monotonic() + 3
  while time.monotonic() < deadline:
    if inhibitors(native) == ["a(ssssuu)", "0"]:
      return
    time.sleep(0.05)
  raise RuntimeError("Inhibitor FD was not released after parent/child completion")


def failure_output(parent):
  """Retain the worker cause before controller failure ends the guest test."""
  Path("/run/native-release").touch()
  try:
    output, _ = parent.communicate(timeout=3)
  except subprocess.TimeoutExpired:
    parent.kill()
    try:
      output, _ = parent.communicate(timeout=3)
    except subprocess.TimeoutExpired as error:
      output = error.output or b""
      if isinstance(output, bytes):
        output = output.decode(errors="replace")
      print("NATIVE_INHIBITOR_WORKER_DRAIN_TIMEOUT", flush=True)
  print("NATIVE_INHIBITOR_WORKER_FAILURE_OUTPUT_BEGIN", flush=True)
  print(output[-65536:], end="", flush=True)
  print("\nNATIVE_INHIBITOR_WORKER_FAILURE_OUTPUT_END exit=" + str(parent.poll()), flush=True)


def power_diagnostics(native):
  """Print raw read-only guest replies without changing the adapter's guard."""
  queries = [("call", native.LOGIN, "ListInhibitors"),
             ("get-property", native.LOGIN, "PreparingForSleep"),
             ("get-property", native.LOGIN, "PreparingForShutdown"),
             ("get-property", native.LOGIN, "ScheduledShutdown"),
             ("call", native.MANAGER, "ListJobs")]
  commands = [(member, ("/usr/bin/busctl", "--system", "--no-pager", "--full", method, *service, member))
              for method, service, member in queries]
  commands.append(("power-units", ("/usr/bin/systemctl", "show", "--no-pager", "--property=Id,LoadState,ActiveState", *native.POWER_UNITS)))
  for name, command in commands:
    try:
      result = subprocess.run(command, capture_output=True, text=True, timeout=2, env=native.ENV)
      record = {"query": name, "returncode": result.returncode, "stdout": result.stdout[-16384:], "stderr": result.stderr[-16384:]}
    except subprocess.TimeoutExpired:
      record = {"query": name, "timeout": True}
    print("NATIVE_INHIBITOR_FAILURE_QUERY " + json.dumps(record), flush=True)


def main():
  native = adapter()
  version = subprocess.run(["/usr/bin/systemd-inhibit", "--version"], check=True, capture_output=True, text=True).stdout
  if not version.splitlines()[0].startswith("systemd 261 (261.2"):
    raise RuntimeError("Proof requires installed systemd 261.2: " + version)
  print("NATIVE_INHIBITOR_SYSTEMD " + version.splitlines()[0], flush=True)
  print("NATIVE_INHIBITOR_SCOPE unchanged read-only guard; stub launcher; no native CLI or transition", flush=True)
  empty(native)
  Path("/run/native-case").write_text("held")
  with subprocess.Popen(native._inhibit_command("activation"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as parent:
    try:
      # A worker crash before readiness reaches EOF and fails this assertion.
      line = parent.stdout.readline().strip()
      print(line, flush=True)
      if line != "NATIVE_INHIBITOR_HELD " + str(parent.pid):
        raise RuntimeError("Native worker did not establish exact real exclusion")
      native._power_idle(parent.pid)
      records = inhibitors(native)
      if records != ["a(ssssuu)", "1", "sleep:shutdown", native.WHO, native.WHY, "block", "0", str(parent.pid)] and records != ["a(ssssuu)", "1", "shutdown:sleep", native.WHO, native.WHY, "block", "0", str(parent.pid)]:
        raise RuntimeError("Real logind owner differs from exact inhibitor parent")
      try:
        native._power_idle(os.getpid())
      except ValueError as error:
        if str(error) != "Parent does not own the exact real block inhibitor":
          raise
        print("NATIVE_INHIBITOR_REJECT wrong-owner-pid " + str(error), flush=True)
      else:
        raise RuntimeError("Wrong inhibitor owner PID was accepted")
      Path("/run/native-release").touch()
      output, _ = parent.communicate(timeout=15)
      print(output, end="", flush=True)
      if parent.returncode != 0 or "NATIVE_INHIBITOR_REPEATED_GUARD_PASS" not in output:
        raise RuntimeError("Repeated real guard failed")
    except Exception:
      failure_output(parent)
      power_diagnostics(native)
      raise
    finally:
      if parent.poll() is None:
        parent.kill()
        parent.wait(timeout=3)
  empty(native)
  print("NATIVE_INHIBITOR_RELEASE_PASS", flush=True)
  try:
    native._power_idle(parent.pid)
  except ValueError as error:
    if str(error) != "Parent does not own the exact real block inhibitor":
      raise
    print("NATIVE_INHIBITOR_REJECT released-owner " + str(error), flush=True)
  else:
    raise RuntimeError("Released inhibitor owner was accepted")
  for case in ("absent", "wrong-command"):
    Path("/run/native-case").write_text(case)
    command = list(native._inhibit_command("activation"))
    if case == "absent":
      command = command[6:]
    else:
      command[3] = "--who=wrong-owner"
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    print(result.stdout, end="", flush=True)
    if result.returncode != 0 or "NATIVE_INHIBITOR_REJECT " + case not in result.stdout:
      raise RuntimeError("Ownership rejection failed: " + result.stderr)
    empty(native)
  print("NATIVE_INHIBITOR_VM_PASS", flush=True)


if __name__ == "__main__":
  main()
