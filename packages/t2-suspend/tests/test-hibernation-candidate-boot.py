#!/usr/bin/env python3
"""Exercise the candidate boot staging transaction against a synthetic ESP."""

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile


package = Path(__file__).resolve().parents[1]
script = package / "experiments/stage-hibernation-candidate-boot.py"
spec = importlib.util.spec_from_file_location("candidate_boot", script)
candidate_boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(candidate_boot)


def efi_string(value):
  return b"\x07\x00\x00\x00" + (value + "\x00").encode("utf-16-le")


def efi_strings(values):
  return b"\x06\x00\x00\x00" + "".join(value + "\x00" for value in values).encode("utf-16-le")


def prepare_fixture(directory):
  root = directory / "root"
  candidate = directory / "candidate"
  production = root / "boot/EFI/Linux/omarchy_linux-t2.efi"
  limine = root / "boot/limine.conf"
  selected = root / candidate_boot.SELECTED
  production.parent.mkdir(parents=True)
  selected.parent.mkdir(parents=True)
  candidate.mkdir()
  production.write_bytes(b"healthy production uki")
  production_blake2 = hashlib.blake2b(production.read_bytes()).hexdigest()
  original_limine = (
    "timeout: 3\n"
    "default_entry: 2\n"
    "/+Omarchy\n"
    "  //linux-t2\n"
    "  protocol: efi\n"
    f"  path: boot():/EFI/Linux/omarchy_linux-t2.efi#{production_blake2}\n"
  )
  limine.write_text(original_limine)
  selected.write_bytes(efi_string("Omarchy.linux-t2"))

  candidate_image = candidate / "mba-t2-hibernation-candidate.efi"
  candidate_image.write_bytes(b"private candidate uki")
  (candidate / "provenance.json").write_text(json.dumps({
    "candidate": "mba-t2-hibernation-module-overlay",
    "candidate_uki_sha256": hashlib.sha256(candidate_image.read_bytes()).hexdigest(),
    "production_uki_sha256": hashlib.sha256(production.read_bytes()).hexdigest(),
    "production_modified": False,
    "installed": False,
    "boot_entry_created": False,
    "hardware_qualified": False,
  }))
  return root, candidate, candidate_image, limine, original_limine


with tempfile.TemporaryDirectory(prefix="t2-candidate-boot-") as directory:
  root, candidate, candidate_image, limine, original_limine = prepare_fixture(Path(directory) / "happy")

  receipt = candidate_boot.stage(root, candidate)
  assert receipt["state"] == "staged"
  assert "default_entry: 2" in limine.read_text()
  assert candidate_boot.BEGIN in limine.read_text()
  assert receipt["entry_id"] == candidate_boot.entry_id(receipt["candidate_uki_sha256"])
  assert "/" + receipt["entry_id"] + "\n" in limine.read_text()
  assert (root / candidate_boot.IMAGE).read_bytes() == candidate_image.read_bytes()
  assert not (root / candidate_boot.ONESHOT).exists()
  try:
    candidate_boot.verify_staged(root, {**receipt, "entry_id": candidate_boot.ENTRY_PREFIX})
    raise AssertionError("candidate entry identifier was not bound to its UKI hash")
  except ValueError as error:
    assert "bound" in str(error)

  try:
    candidate_boot.arm(root, runner=lambda *_args, **_kwargs: None)
    raise AssertionError("candidate armed before Limine advertised its entry")
  except ValueError as error:
    assert "advertised" in str(error)

  entries = root / candidate_boot.ENTRIES
  entries.write_bytes(efi_strings(("Omarchy.linux-t2", receipt["entry_id"])))
  sync_calls = []

  def fake_bootctl(arguments, check):
    assert arguments == ["bootctl", "set-oneshot", receipt["entry_id"]]
    assert check
    assert sync_calls == [True]
    (root / candidate_boot.ONESHOT).write_bytes(efi_string(receipt["entry_id"]))

  armed = candidate_boot.arm(root, runner=fake_bootctl, sync=lambda: sync_calls.append(True))
  assert armed["state"] == "arming"
  assert candidate_boot.read_efi_string(root / candidate_boot.ONESHOT) == receipt["entry_id"]

  try:
    candidate_boot.rollback(root)
    raise AssertionError("armed candidate rollback was not blocked")
  except ValueError as error:
    assert "Disarm" in str(error)
  try:
    candidate_boot.clear_rolled_back(root)
    raise AssertionError("armed candidate state clear was not blocked")
  except ValueError as error:
    assert "Disarm" in str(error)

  (root / candidate_boot.ONESHOT).unlink()
  try:
    candidate_boot.clear_rolled_back(root)
    raise AssertionError("staged candidate state was cleared before rollback")
  except ValueError as error:
    assert "rolled back" in str(error)
  rolled_back = candidate_boot.rollback(root)
  assert rolled_back["state"] == "rolled-back"
  assert limine.read_text() == original_limine
  assert not (root / candidate_boot.IMAGE).exists()
  try:
    candidate_boot.stage(root, candidate)
    raise AssertionError("staging replaced an uncleared transaction")
  except ValueError as error:
    assert "already exists" in str(error)
  cleared = candidate_boot.clear_rolled_back(root)
  assert cleared["state"] == "cleared"
  assert not (root / candidate_boot.STATE).exists()
  assert candidate_boot.clear_rolled_back(root) == {"state": "cleared"}
  restaged = candidate_boot.stage(root, candidate)
  assert restaged["state"] == "staged"
  assert candidate_boot.rollback(root)["state"] == "rolled-back"
  receipt_path = root / candidate_boot.RECEIPT
  backup_path = root / candidate_boot.BACKUP
  backup_data = backup_path.read_bytes()
  backup_path.write_bytes(b"changed backup")
  try:
    candidate_boot.clear_rolled_back(root)
    raise AssertionError("changed rollback backup was cleared")
  except ValueError as error:
    assert "backup changed" in str(error)
  backup_path.write_bytes(backup_data)
  unknown = root / candidate_boot.STATE / "unknown"
  unknown.write_text("unexpected state")
  try:
    candidate_boot.clear_rolled_back(root)
    raise AssertionError("unknown transaction state was cleared")
  except ValueError as error:
    assert "unknown files" in str(error)
  unknown.unlink()
  backup_path.unlink()
  assert candidate_boot.clear_rolled_back(root)["state"] == "cleared"
  assert not receipt_path.exists()
  assert not (root / candidate_boot.STATE).exists()

  original_writer = candidate_boot.atomic_write
  for fail_at in (1, 2, 3, 4, 5):
    case = Path(directory) / ("failure-" + str(fail_at))
    root, candidate, _candidate_image, limine, original_limine = prepare_fixture(case)
    writes = [0]

    def failing_writer(path, data, mode):
      writes[0] += 1
      original_writer(path, data, mode)
      if writes[0] == fail_at:
        raise RuntimeError("injected write failure")

    candidate_boot.atomic_write = failing_writer
    try:
      try:
        candidate_boot.stage(root, candidate)
        raise AssertionError("injected staging failure was ignored")
      except RuntimeError as error:
        assert "injected write failure" in str(error)
    finally:
      candidate_boot.atomic_write = original_writer

    assert limine.read_text() == original_limine
    assert not (root / candidate_boot.IMAGE).exists()
    if fail_at == 1:
      assert not (root / candidate_boot.STATE).exists()
    else:
      recovered = candidate_boot.load_receipt(root)
      assert recovered["state"] == "stage-failed-recovered"
      candidate_boot.verify_recovered(root, recovered)
      assert candidate_boot.rollback(root)["state"] == "rolled-back"

  for fail_at in (1, 2, 3):
    case = Path(directory) / ("rollback-failure-" + str(fail_at))
    root, candidate, _candidate_image, limine, original_limine = prepare_fixture(case)
    candidate_boot.stage(root, candidate)
    writes = [0]

    def failing_rollback_writer(path, data, mode):
      writes[0] += 1
      original_writer(path, data, mode)
      if writes[0] == fail_at:
        raise RuntimeError("injected rollback failure")

    candidate_boot.atomic_write = failing_rollback_writer
    try:
      try:
        candidate_boot.rollback(root)
        raise AssertionError("injected rollback failure was ignored")
      except RuntimeError as error:
        assert "injected rollback failure" in str(error)
    finally:
      candidate_boot.atomic_write = original_writer

    assert candidate_boot.rollback(root)["state"] == "rolled-back"
    assert limine.read_text() == original_limine
    assert not (root / candidate_boot.IMAGE).exists()

  for fail_at in (1, 2):
    case = Path(directory) / ("clear-failure-" + str(fail_at))
    root, candidate, _candidate_image, limine, original_limine = prepare_fixture(case)
    candidate_boot.stage(root, candidate)
    candidate_boot.rollback(root)
    unlinks = [0]

    def failing_unlink(path):
      unlinks[0] += 1
      path.unlink()
      if unlinks[0] == fail_at:
        raise RuntimeError("injected clear failure")

    try:
      candidate_boot.clear_rolled_back(root, unlink=failing_unlink)
      raise AssertionError("injected clear failure was ignored")
    except RuntimeError as error:
      assert "injected clear failure" in str(error)

    assert candidate_boot.clear_rolled_back(root)["state"] == "cleared"
    assert limine.read_text() == original_limine
    assert not (root / candidate_boot.STATE).exists()

print("PASS: candidate boot stages transactionally, requires a loader refresh, arms once and restores production exactly")
