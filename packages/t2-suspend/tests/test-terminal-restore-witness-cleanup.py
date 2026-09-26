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
  guard = (m.SOURCE_BOOT + "\n").encode()
  assert hashlib.sha256(guard).hexdigest() == m.GUARD_SHA
  attempt = json.dumps({"transition_vector": m.VECTOR, "boot_id": m.SOURCE_BOOT,
                        "state": "transition-armed", "real_s4_attempted": True}).encode()
  m.ATTEMPT_SHA = hashlib.sha256(attempt).hexdigest()
  values = {
    m.SOURCE_VAR: b"\x07\0\0\0MBPW" + bytes.fromhex(m.VECTOR[:24]) + b"\x04",
    m.RESTORE_VAR: b"\x07\0\0\0MBRS" + bytes.fromhex(m.VECTOR[:24]) + bytes((m.RESTORE_STAGE,)),
    m.ENTERED: b"\x07\0\0\0MBRH" + m.VECTOR[:24].encode() + b"\x01",
    m.ARMED: b"\x07\0\0\0MBRH" + m.VECTOR[:24].encode() + b"\x02",
    "receipt.json": b'{"fixture":"archived receipt"}\n',
    "recovery-acceptance-v3.json": b'{"fixture":"archived acceptance"}\n',
  }
  for name in m.PINS:
    if name not in values:
      if name.startswith("OmarchyT2ColdPreCpuReturned"):
        values[name] = b"\x07\0\0\0MBCP" + m.VECTOR[:24].encode() + b"\x01"
      elif name.startswith("OmarchyT2ColdPreSyscoreReturned"):
        values[name] = b"\x07\0\0\0MBSC" + m.VECTOR[:24].encode() + b"\x01"
      elif name == "s4-attempted":
        values[name] = guard
      elif name == "attempt.json":
        values[name] = attempt
      else:
        assert name.endswith(".json"), name
        values[name] = json.dumps({"fixture": name, "vector": m.VECTOR}).encode()
  for name, value in values.items():
    if name.endswith(".json"):
      m.PINS[name] = hashlib.sha256(value).hexdigest()
    else:
      assert hashlib.sha256(value).hexdigest() == m.PINS[name]
    write(root, m.ARCHIVE / name, value)
  (root / m.ARCHIVE).chmod(0o700)
  for name, relative in m.TARGETS.items():
    write(root, relative, values[name])
  for name in m.preserved_live_pins():
    write(root, Path("sys/firmware/efi/efivars") / name, values[name])
  write(root, m.GUARD, guard)
  write(root, m.ATTEMPT, attempt)


def stock(root):
  return m.RETURN_BOOTS.get(m.VECTOR, RETURN_BOOT)


def refused(function):
  try:
    function()
  except (ValueError, OSError):
    return
  raise AssertionError("Unsafe cleanup was accepted")


with tempfile.TemporaryDirectory(prefix="terminal-witness-cleanup-") as temporary:
  base = Path(temporary)
  cases = ("success", "archive", "live", "guard", "missing", "symlink", "mode", "witness", "intent", "partial", "boot",
           "live-returned", "archive-returned", "missing-returned", "symlink-returned", "wrong-return-boot")
  assert len(m.TERMINALS) == 5
  refused(lambda: m.select_terminal("0" * 64))
  for vector, case in ((vector, case) for vector in m.TERMINALS for case in cases):
    m.select_terminal(vector)
    returned = next((name for name in m.preserved_live_pins() if name.startswith(("OmarchyT2ColdPreCpuReturned", "OmarchyT2ColdPreSyscoreReturned"))), None)
    if case.endswith("returned") and returned is None:
      continue
    root = base / vector / case
    fixture(root)
    if case == "success":
      before = {name: (root / m.ARCHIVE / name).read_bytes() for name in m.PINS}
      live_before = {name: (root / "sys/firmware/efi/efivars" / name).read_bytes() for name in m.preserved_live_pins()}
      unrelated = write(root, Path("sys/firmware/efi/efivars/old-stage-variable"), b"old evidence")
      m.validate(root, stock)
      assert not (root / m.ARCHIVE / "slot-clear-intent.json").exists()
      result = m.execute(root, stock, Path.unlink)
      assert result["guards_and_witnesses_preserved"]
      assert all(not (root / relative).exists() for relative in m.TARGETS.values())
      assert all((root / m.ARCHIVE / name).read_bytes() == value for name, value in before.items())
      assert all((root / "sys/firmware/efi/efivars" / name).read_bytes() == value for name, value in live_before.items())
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
    elif case == "wrong-return-boot":
      if vector in m.RETURN_BOOTS:
        refused(lambda: m.execute(root, lambda _: RETURN_BOOT, Path.unlink))
        assert not (root / m.ARCHIVE / "slot-clear-intent.json").exists()
      else:
        assert m.validate(root, lambda _: RETURN_BOOT)["return_boot_id"] == RETURN_BOOT
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
      elif case == "live-returned":
        (root / "sys/firmware/efi/efivars" / returned).write_bytes(b"changed returned witness")
      elif case == "archive-returned":
        (root / m.ARCHIVE / returned).write_bytes(b"changed archived returned witness")
      elif case == "missing-returned":
        (root / "sys/firmware/efi/efivars" / returned).unlink()
      elif case == "symlink-returned":
        target = root / "sys/firmware/efi/efivars" / returned
        target.unlink()
        target.symlink_to(root / m.ARCHIVE / returned)
      refused(lambda: m.execute(root, stock, Path.unlink))
      if case != "intent":
        assert not (root / m.ARCHIVE / "slot-clear-intent.json").exists()

  # Exercise current_stock itself on a portable filesystem. Only selected-entry
  # lookup and physical-root inspection are stubbed; PM/kernel/resume/module
  # gates and production hash checks execute their real validator logic.
  m.select_terminal(next(iter(m.TERMINALS)))
  stock_root = base / "stock-module-gate"
  for relative, value in {
    "proc/sys/kernel/osrelease": b"7.2.6-arch2-Watanare-T2-2-t2\n",
    "proc/sys/kernel/random/boot_id": RETURN_BOOT.encode() + b"\n",
    "sys/devices/virtual/dmi/id/product_name": b"MacBookAir9,1\n",
    "sys/power/pm_test": b"[none] freezer devices platform processors core\n",
    "sys/power/disk": b"[platform] shutdown\n",
    "sys/power/pm_trace": b"0\n",
    "sys/power/resume": b"253:0\n",
    "sys/power/resume_offset": b"1923214\n",
    "boot/EFI/Linux/omarchy_linux-t2.efi": b"synthetic production image",
  }.items():
    write(stock_root, Path(relative), value)
  selected_entry = m.PAIR.selected_entry
  verify_primary_root = m.SOURCE.verify_primary_root
  production_sha = m.PRODUCTION_SHA
  try:
    m.PAIR.selected_entry = lambda _: "Omarchy.linux-t2"
    m.SOURCE.verify_primary_root = lambda _: None
    m.PRODUCTION_SHA = hashlib.sha256(b"synthetic production image").hexdigest()
    assert {"mba_hibernate_cold_pre_cpu", "mba_hibernate_cold_pre_syscore", "mba_hibernate_cold_pre_arch"}.issubset(m.NO_CURRENT_MODULES)
    for vector in m.TERMINALS:
      m.select_terminal(vector)
      assert m.current_stock(stock_root) == RETURN_BOOT
      for name in m.NO_CURRENT_MODULES:
        loaded = stock_root / "sys/module" / name
        loaded.mkdir(parents=True)
        refused(lambda: m.current_stock(stock_root))
        loaded.rmdir()
      assert m.current_stock(stock_root) == RETURN_BOOT
  finally:
    m.PAIR.selected_entry = selected_entry
    m.SOURCE.verify_primary_root = verify_primary_root
    m.PRODUCTION_SHA = production_sha

print("PASS: terminal EFI slot cleanup preserves archives/guards/witnesses and fails closed on changed evidence")
