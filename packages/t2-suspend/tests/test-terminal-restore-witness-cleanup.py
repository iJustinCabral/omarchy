#!/usr/bin/python3
"""Fault-test the exact terminal marker cleanup without EFI or PM writes."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


source = Path(__file__).resolve().parents[1] / "experiments/cleanup-terminal-restore-witness.py"
spec = importlib.util.spec_from_file_location("terminal_cleanup_test", source)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
RETURN_BOOT = "9459059b-06e2-4673-95bb-84b3d58427eb"


def write(root, relative, value, mode=0o600):
  target = root / relative
  target.parent.mkdir(parents=True, exist_ok=True)
  target.write_bytes(value)
  target.chmod(mode)
  return target


def fixture(root):
  values = {
    m.SOURCE_VAR: b"\x07\0\0\0MBPW" + bytes.fromhex(m.VECTOR[:24]) + b"\x04",
    m.RESTORE_VAR: b"\x07\0\0\0MBRS" + bytes.fromhex(m.VECTOR[:24]) + b"\x00",
    m.ENTERED: b"\x07\0\0\0MBRH" + m.VECTOR[:24].encode() + b"\x01",
    m.ARMED: b"\x07\0\0\0MBRH" + m.VECTOR[:24].encode() + b"\x02",
    "receipt.json": b'{"fixture":"archived receipt"}\n',
    "recovery-acceptance-v3.json": b'{"fixture":"archived acceptance"}\n',
  }
  for name, value in values.items():
    if name.endswith(".json"):
      m.PINS[name] = hashlib.sha256(value).hexdigest()
    else:
      assert hashlib.sha256(value).hexdigest() == m.PINS[name]
    write(root, m.ARCHIVE / name, value)
  (root / m.ARCHIVE).chmod(0o700)
  for name, relative in m.TARGETS.items():
    write(root, relative, values[name])
  for name in (m.ENTERED, m.ARMED):
    write(root, Path("sys/firmware/efi/efivars") / name, values[name])
  guard = (m.SOURCE_BOOT + "\n").encode()
  assert hashlib.sha256(guard).hexdigest() == m.GUARD_SHA
  write(root, m.GUARD, guard)
  attempt = json.dumps({"transition_vector": m.VECTOR, "boot_id": m.SOURCE_BOOT,
                        "state": "transition-armed", "real_s4_attempted": True}).encode()
  m.ATTEMPT_SHA = hashlib.sha256(attempt).hexdigest()
  write(root, m.ATTEMPT, attempt)


def stock(root):
  return RETURN_BOOT


def refused(function):
  try:
    function()
  except (ValueError, OSError):
    return
  raise AssertionError("Unsafe cleanup was accepted")


with tempfile.TemporaryDirectory(prefix="terminal-witness-cleanup-") as temporary:
  base = Path(temporary)
  for case in ("success", "archive", "live", "guard", "missing", "symlink", "mode", "witness", "intent", "partial", "boot"):
    root = base / case
    fixture(root)
    if case == "success":
      before = {name: (root / m.ARCHIVE / name).read_bytes() for name in m.PINS}
      unrelated = write(root, Path("sys/firmware/efi/efivars/old-stage-variable"), b"old evidence")
      m.validate(root, stock)
      assert not (root / m.ARCHIVE / "slot-clear-intent.json").exists()
      result = m.execute(root, stock, Path.unlink)
      assert result["guards_and_witnesses_preserved"]
      assert all(not (root / relative).exists() for relative in m.TARGETS.values())
      assert all((root / m.ARCHIVE / name).read_bytes() == value for name, value in before.items())
      assert (root / m.GUARD).exists() and (root / m.ATTEMPT).exists() and unrelated.read_bytes() == b"old evidence"
      assert m.execute(root, stock, Path.unlink) == result
      write(root, m.BACKEND.V3_VARIABLE, before[m.SOURCE_VAR])
      refused(lambda: m.execute(root, stock, Path.unlink))
    elif case == "partial":
      calls = []
      def fail_second(target):
        calls.append(target)
        if len(calls) == 2:
          raise OSError("simulated removal fault")
        target.unlink()
      refused(lambda: m.execute(root, stock, fail_second))
      assert (root / m.ARCHIVE / "slot-clear-intent.json").exists()
      assert not (root / m.ARCHIVE / "slot-clear-complete.json").exists()
      assert m.execute(root, stock, Path.unlink)["slots_cleared"]
    elif case == "boot":
      m.execute(root, stock, Path.unlink)
      refused(lambda: m.validate(root, lambda _: m.SOURCE_BOOT))
    else:
      if case == "archive":
        (root / m.ARCHIVE / m.SOURCE_VAR).write_bytes(b"changed archive")
      elif case == "live":
        (root / m.BACKEND.V3_VARIABLE).write_bytes(b"changed live value")
      elif case == "guard":
        (root / m.GUARD).write_bytes(b"changed guard")
      elif case == "missing":
        (root / m.BACKEND.V3_VARIABLE).unlink()
      elif case == "symlink":
        target = root / m.BACKEND.V3_VARIABLE
        target.unlink()
        target.symlink_to(root / m.ARCHIVE / m.SOURCE_VAR)
      elif case == "mode":
        (root / m.ARCHIVE).chmod(0o755)
      elif case == "witness":
        (root / "sys/firmware/efi/efivars" / m.ARMED).write_bytes(b"changed witness")
      elif case == "intent":
        write(root, m.ARCHIVE / "slot-clear-intent.json", b"{}\n")
      refused(lambda: m.execute(root, stock, Path.unlink))
      if case != "intent":
        assert not (root / m.ARCHIVE / "slot-clear-intent.json").exists()

print("PASS: terminal EFI slot cleanup preserves archives/guards/witnesses and fails closed on changed evidence")
