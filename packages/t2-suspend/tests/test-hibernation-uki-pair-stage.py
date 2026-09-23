#!/usr/bin/python3
"""Exercise two-entry hibernation boot staging without touching the host ESP."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


script = Path(__file__).resolve().parents[1] / "experiments/stage-hibernation-uki-pair.py"
spec = importlib.util.spec_from_file_location("hibernation_pair_stage", script)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


def sha(data):
  return hashlib.sha256(data).hexdigest()


def efi_string(value):
  return b"\x07\x00\x00\x00" + (value + "\x00").encode("utf-16-le")


def efi_strings(values):
  return b"\x06\x00\x00\x00" + "".join(value + "\x00" for value in values).encode("utf-16-le")


def rejects(action, expected):
  try:
    action()
  except ValueError as error:
    assert expected in str(error), error
  else:
    raise AssertionError("Unsafe pair action accepted: " + expected)


def objcopy(*arguments):
  subprocess.run(("objcopy", *map(str, arguments)), check=True, capture_output=True)


def publish(directory, role, production):
  directory.mkdir()
  initrd = (role + "-private-initrd").encode()
  initrd_path = directory / "mba-t2-hibernation-candidate.initrd"
  image_path = directory / "mba-t2-hibernation-candidate.efi"
  initrd_path.write_bytes(initrd)
  objcopy("--add-section=.initrd=" + str(initrd_path), production, image_path)
  image = image_path.read_bytes()
  modules = {
    name: {
      "source": "drivers/" + name + ".ko",
      "sha256": sha(name.encode()),
      "srcversion": "TEST" + name,
      "vermagic": "test-kernel SMP preempt mod_unload",
    }
    for name in stage.AUDIT.S4.RUNTIME_MODULES
  }
  report = {
    "candidate": "mba-t2-hibernation-early-source" if role == "source" else "mba-t2-hibernation-module-overlay",
    "experiment_id": "pair-test-" + role,
    "candidate_uki_sha256": sha(image),
    "candidate_initrd_sha256": sha(initrd),
    "cmdline": "root=/dev/mapper/root resume=/dev/mapper/root",
    "kernel_release": "test-kernel",
    "modules": modules,
    "production_uki_sha256": sha(production.read_bytes()),
    "source_provenance_sha256": "b" * 64,
    "unchanged_production_sections_sha256": {
      section: sha(section.encode()) for section in stage.AUDIT.S4.RUNTIME_SECTIONS
    },
    "installed": False,
    "boot_entry_created": False,
    "hardware_qualified": False,
    "production_modified": False,
  }
  if role == "source":
    report.update({
      "initrd_module_selection": {
        name: "usr/lib/modules/test-kernel/" + name + ".ko"
        for name in stage.AUDIT.SOURCE_INITRD_MODULES
      },
      "pre_restore_module_policy": "early-t2-radio",
    })
  else:
    report.update({
      "initrd_module_selection": {},
      "pre_restore_module_policy": "root-only-no-t2-radio",
      "pre_restore_excluded_modules": sorted(stage.AUDIT.S4.RUNTIME_MODULES),
      "post_switch_root_payload": {
        name: "usr/lib/omarchy-t2-hibernation-candidate/payload/" + name + ".ko"
        for name in stage.AUDIT.S4.RUNTIME_MODULES
      },
    })
  (directory / "provenance.json").write_text(json.dumps(report))


def fixture(directory):
  root = directory / "root"
  production = root / "boot/EFI/Linux/omarchy_linux-t2.efi"
  production.parent.mkdir(parents=True)
  kernel = directory / "kernel"
  cmdline = directory / "cmdline"
  kernel.write_bytes(b"healthy production kernel")
  cmdline.write_bytes(b"root=/dev/mapper/root resume=/dev/mapper/root\x00")
  objcopy(
    "--add-section=.linux=" + str(kernel),
    "--add-section=.cmdline=" + str(cmdline),
    "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
    production,
  )
  limine = root / stage.SINGLE.LIMINE
  original = (
    "timeout: 3\n"
    "default_entry: 2\n"
    "/+Omarchy\n"
    "  //linux-t2\n"
    "  protocol: efi\n"
    "  path: boot():/EFI/Linux/omarchy_linux-t2.efi#"
    + hashlib.blake2b(production.read_bytes()).hexdigest() + "\n"
  )
  limine.write_text(original)
  selected = root / stage.SINGLE.SELECTED
  selected.parent.mkdir(parents=True)
  selected.write_bytes(efi_string("Omarchy.linux-t2"))
  boot_id = root / stage.BOOT_ID
  boot_id.parent.mkdir(parents=True)
  boot_id.write_text("11111111-2222-3333-4444-555555555555\n")
  source = directory / "source"
  restore = directory / "restore"
  publish(source, "source", production)
  publish(restore, "restore", production)
  return root, source, restore, limine, original


with tempfile.TemporaryDirectory(prefix="t2-hibernation-pair-rejected-") as temporary:
  rejected_hash = "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd"
  root, source, restore, _limine, _original = fixture(Path(temporary) / "rejected-stage")
  original_loader = stage.AUDIT.load_candidate

  def rejected_loader(directory, role):
    report = original_loader(directory, role)
    if role == "source":
      report["candidate_uki_sha256"] = rejected_hash
    return report

  stage.AUDIT.load_candidate = rejected_loader
  try:
    rejects(lambda: stage.stage(root, source, restore), "failed ordinary root mount")
  finally:
    stage.AUDIT.load_candidate = original_loader
  assert not (root / stage.RECEIPT).exists()

  root, source, restore, _limine, _original = fixture(Path(temporary) / "replaced-kernel")

  def replaced_kernel_loader(directory, role):
    report = original_loader(directory, role)
    if role == "source":
      report["modified_sections_sha256"] = {".linux": "c" * 64}
      report["unchanged_production_sections_sha256"].pop(".linux")
    return report

  stage.AUDIT.load_candidate = replaced_kernel_loader
  try:
    rejects(lambda: stage.stage(root, source, restore), "replaces the production kernel")
  finally:
    stage.AUDIT.load_candidate = original_loader
  assert not (root / stage.RECEIPT).exists()

  for role in ("source", "restore"):
    for section in (".linux", ".cmdline"):
      root, source, restore, limine, original = fixture(Path(temporary) / ("actual-" + role + "-" + section[1:]))
      directory = source if role == "source" else restore
      replacement_section = directory / "changed-section"
      replacement_section.write_bytes(b"different physical boot section")
      image = directory / "mba-t2-hibernation-candidate.efi"
      replacement_image = directory / "replacement.efi"
      objcopy("--update-section=" + section + "=" + str(replacement_section), image, replacement_image)
      replacement_image.replace(image)
      report_path = directory / "provenance.json"
      report = json.loads(report_path.read_text())
      report["candidate_uki_sha256"] = sha(image.read_bytes())
      report_path.write_text(json.dumps(report))
      rejects(lambda: stage.stage(root, source, restore), role + " UKI " + section + " differs from production")
      assert limine.read_text() == original
      assert not (root / stage.RECEIPT).exists()

  root, source, restore, _limine, _original = fixture(Path(temporary) / "rejected-arm")
  receipt = stage.stage(root, source, restore)
  receipt["images"]["source"]["sha256"] = rejected_hash
  stage.save_receipt(root, receipt)
  rejects(lambda: stage.arm_source(root), "failed ordinary root mount")
  assert not (root / stage.SINGLE.ONESHOT).exists()

  root, source, restore, _limine, _original = fixture(Path(temporary) / "missing-kernel-policy")
  receipt = stage.stage(root, source, restore)
  receipt.pop("kernel_policy")
  stage.save_receipt(root, receipt)
  rejects(lambda: stage.arm_source(root), "production-kernel boot policy")
  assert not (root / stage.SINGLE.ONESHOT).exists()


with tempfile.TemporaryDirectory(prefix="t2-hibernation-pair-stage-") as temporary:
  base = Path(temporary)
  root, source, restore, limine, original = fixture(base / "happy")
  receipt = stage.stage(root, source, restore)
  assert receipt["state"] == "staged"
  assert receipt["runtime_stack_sha256"] == stage.AUDIT.audit(
    stage.AUDIT.load_candidate(source, "source"), stage.AUDIT.load_candidate(restore, "restore")
  )["runtime_stack_sha256"]
  assert limine.read_text().count("default_entry: 2") == 1
  assert limine.read_text().count(stage.BEGIN) == 1
  assert not (root / stage.SINGLE.ONESHOT).exists()
  for role, image in stage.IMAGES.items():
    assert (root / image).read_bytes() == (source if role == "source" else restore).joinpath("mba-t2-hibernation-candidate.efi").read_bytes()
    assert "/" + receipt["images"][role]["entry_id"] + "\n" in limine.read_text()
  stage.verify_staged(root, receipt)
  evidence = root / stage.STATE / "s4-vectors"
  evidence.mkdir()
  (evidence / "guard").write_text("preserve")

  rejects(lambda: stage.arm_source(root), "advertisement is missing")
  entries = root / stage.SINGLE.ENTRIES
  entries.write_bytes(efi_strings(("Omarchy.linux-t2", *(receipt["images"][role]["entry_id"] for role in stage.IMAGES))))
  sync_calls = []

  def bootctl(arguments, check):
    assert arguments[:2] == ["bootctl", "set-oneshot"] and check
    if arguments[2]:
      assert sync_calls
    oneshot = root / stage.SINGLE.ONESHOT
    if arguments[2]:
      oneshot.write_bytes(efi_string(arguments[2]))
    else:
      oneshot.unlink()

  armed_source = stage.arm_source(root, runner=bootctl, sync=lambda: sync_calls.append(True))
  assert armed_source["state"] == "source-arming"
  assert stage.SINGLE.read_efi_string(root / stage.SINGLE.ONESHOT) == receipt["images"]["source"]["entry_id"]
  rejects(lambda: stage.rollback(root), "Disarm")
  rejects(lambda: stage.clear_rolled_back(root), "Disarm")
  (root / stage.SINGLE.ONESHOT).unlink()
  rejects(lambda: stage.arm_restore(root, runner=bootctl), "not the exact source")
  (root / stage.SINGLE.SELECTED).write_bytes(efi_string(receipt["images"]["source"]["entry_id"]))
  rejects(lambda: stage.arm_restore(root, runner=bootctl), "not consumed by a new boot")
  (root / stage.BOOT_ID).write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
  armed_restore = stage.arm_restore(root, runner=bootctl, sync=lambda: sync_calls.append(True))
  assert armed_restore["state"] == "restore-arming"
  assert stage.SINGLE.read_efi_string(root / stage.SINGLE.ONESHOT) == receipt["images"]["restore"]["entry_id"]
  (root / stage.SINGLE.ONESHOT).write_bytes(efi_string("Unrelated"))
  rejects(lambda: stage.disarm_restore(root, runner=bootctl), "unknown one-shot")
  (root / stage.SINGLE.ONESHOT).write_bytes(efi_string(receipt["images"]["restore"]["entry_id"]))
  assert stage.disarm_restore(root, runner=bootctl)["state"] == "restore-disarmed"
  rejects(lambda: stage.arm_restore(root, runner=bootctl), "not armed and consumed")
  (root / stage.SINGLE.SELECTED).write_bytes(efi_string("Omarchy.linux-t2"))
  assert stage.rollback(root)["state"] == "rolled-back"
  assert limine.read_text() == original
  assert all(not (root / image).exists() for image in stage.IMAGES.values())
  rejects(lambda: stage.stage(root, source, restore), "already exists")
  assert stage.clear_rolled_back(root)["state"] == "cleared"
  assert (evidence / "guard").read_text() == "preserve"
  assert not (root / stage.RECEIPT).exists()
  assert not (root / stage.BACKUP).exists()

  root, source, restore, _limine, _original = fixture(base / "tamper")
  tampered = stage.stage(root, source, restore)
  (root / stage.IMAGES["restore"]).write_bytes(b"unknown image")
  rejects(lambda: stage.verify_staged(root, tampered), "restore image changed")
  rejects(lambda: stage.rollback(root), "restore image changed")

  original_writer = stage.atomic_write
  for fail_at in range(1, 7):
    root, source, restore, limine, original = fixture(base / ("stage-failure-" + str(fail_at)))
    writes = [0]

    def failing_write(path, data, mode):
      writes[0] += 1
      original_writer(path, data, mode)
      if writes[0] == fail_at:
        raise RuntimeError("injected stage failure")

    stage.atomic_write = failing_write
    try:
      try:
        stage.stage(root, source, restore)
      except RuntimeError as error:
        assert "injected stage failure" in str(error)
      else:
        raise AssertionError("Injected pair stage failure was ignored")
    finally:
      stage.atomic_write = original_writer
    assert limine.read_text() == original
    assert all(not (root / image).exists() for image in stage.IMAGES.values())
    if fail_at == 1:
      assert not (root / stage.STATE).exists()
    else:
      recovered = stage.load_receipt(root)
      assert recovered["state"] == "stage-failed-recovered"
      stage.verify_recovered(root, recovered)
      assert stage.rollback(root)["state"] == "rolled-back"

  for fail_at in range(1, 4):
    root, source, restore, limine, original = fixture(base / ("rollback-failure-" + str(fail_at)))
    stage.stage(root, source, restore)
    writes = [0]

    def failing_rollback(path, data, mode):
      writes[0] += 1
      original_writer(path, data, mode)
      if writes[0] == fail_at:
        raise RuntimeError("injected rollback failure")

    stage.atomic_write = failing_rollback
    try:
      try:
        stage.rollback(root)
      except RuntimeError as error:
        assert "injected rollback failure" in str(error)
      else:
        raise AssertionError("Injected pair rollback failure was ignored")
    finally:
      stage.atomic_write = original_writer
    assert stage.rollback(root)["state"] == "rolled-back"
    assert limine.read_text() == original

  root, source, restore, _limine, _original = fixture(base / "legacy-conflict")
  legacy_backup = root / stage.SINGLE.BACKUP
  legacy_backup.parent.mkdir(parents=True)
  legacy_backup.write_text("old transaction")
  rejects(lambda: stage.stage(root, source, restore), "legacy candidate")

print("PASS: private hibernation pair stages, arms and recovers offline with exact stock fallback")
