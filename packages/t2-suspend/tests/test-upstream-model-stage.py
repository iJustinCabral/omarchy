#!/usr/bin/python3
"""Exercise the single-image upstream-model stager against a fake ESP, Limine, efivars and product state."""

import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from upstream_model_fixture import *  # noqa: F401,F403 (shared fake ESP, Limine, efivars and product state)


def tree_state(root):
  result = {}
  for relative in (stage.PAIR_STATE, stage.PRODUCT_STATE):
    for path in sorted((root / relative).rglob("*")) if (root / relative).exists() else []:
      result[str(path)] = path.read_bytes() if path.is_file() else None
  return result


with tempfile.TemporaryDirectory(prefix="t2-upstream-stage-refusals-") as temporary:
  base = Path(temporary)

  root, build, limine, original, production = fixture(base / "no-maintenance", maintenance=False)
  rejects(lambda: stage.stage(root, build), "not in package maintenance")
  assert limine.read_text() == original and not (root / stage.C.STATE).exists()

  for name in ("boot-policy.json", "source-default-activation.pending", "runtime-upgrade.pending"):
    root, build, limine, original, production = fixture(base / ("active-" + name))
    (root / stage.PRODUCT_STATE / name).write_text("x")
    rejects(lambda: stage.stage(root, build), "not inactive")
  root, build, limine, original, production = fixture(base / "opt-in")
  (root / "etc/omarchy").mkdir(parents=True)
  (root / "etc/omarchy/t2-hibernate-product.enabled").write_text("")
  rejects(lambda: stage.stage(root, build), "not inactive")

  root, build, limine, original, production = fixture(base / "symlink-marker")
  (root / stage.MAINTENANCE).unlink()
  (root / stage.MAINTENANCE).symlink_to("elsewhere")
  rejects(lambda: stage.stage(root, build), "Refusing symlink")

  root, build, limine, original, production = fixture(base / "default")
  (root / stage.DEFAULT).write_bytes(efi_string("x"))
  rejects(lambda: stage.stage(root, build), "ersistent EFI default")

  root, build, limine, original, production = fixture(base / "oneshot")
  (root / stage.ONESHOT).write_bytes(efi_string("x"))
  rejects(lambda: stage.stage(root, build), "already armed")

  root, build, limine, original, production = fixture(base / "not-stock")
  set_boot(root, "Something.else", BOOT_A)
  rejects(lambda: stage.stage(root, build), "not the healthy stock")

  root, build, limine, original, production = fixture(base / "rejected-static")
  assert "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd" in stage.rejected_hashes(root)
  rejects(lambda: stage.reject_image(root, "974246c01bdc329917651b35f5dbe0b80e2f5e4125987f7c0050e20e4fc39ffd"), "rejected, consumed or terminal")
  original_hashes = stage.rejected_hashes
  stage.rejected_hashes = lambda _root: {sha((build / C.BUILD_IMAGE).read_bytes())}
  try:
    rejects(lambda: stage.stage(root, build), "rejected, consumed or terminal")
  finally:
    stage.rejected_hashes = original_hashes
  assert not (root / stage.ESP_IMAGE).exists()

  # Pair tooling evidence is read but never written; its hashes are refused.
  root, build, limine, original, production = fixture(base / "pair-evidence")
  data = (build / C.BUILD_IMAGE).read_bytes()
  (root / stage.PAIR_STATE / "receipt.json").write_text(json.dumps({"images": {"restore": {"sha256": sha(data)}}}))
  rejects(lambda: stage.stage(root, build), "rejected, consumed or terminal")
  (root / stage.PAIR_STATE / "receipt.json").write_text("{}")
  (root / stage.PAIR_STATE / "s4-vectors").mkdir()
  (root / stage.PAIR_STATE / "s4-vectors" / sha(data)).mkdir()
  rejects(lambda: stage.stage(root, build), "rejected, consumed or terminal")

  for section in (".linux", ".cmdline"):
    root, build, limine, original, production = fixture(base / ("section" + section))
    replacement = base / ("replacement" + section)
    replacement.write_bytes(b"different physical boot section")
    image = build / C.BUILD_IMAGE
    changed = base / ("changed" + section + ".efi")
    objcopy("--update-section=" + section + "=" + str(replacement), image, changed)
    changed.replace(image)
    image.chmod(0o600)
    report = json.loads((build / C.BUILD_PROVENANCE).read_text())
    report["candidate_uki_sha256"] = sha(image.read_bytes())
    (build / C.BUILD_PROVENANCE).write_text(json.dumps(report))
    rejects(lambda: stage.stage(root, build), section + " differs from production")
    assert limine.read_text() == original and not (root / stage.ESP_IMAGE).exists()

  def mutate_case(name, expected, change):
    root, build, limine, original, production = fixture(base / name)
    report = json.loads((build / C.BUILD_PROVENANCE).read_text())
    change(report)
    (build / C.BUILD_PROVENANCE).write_text(json.dumps(report))
    rejects(lambda: stage.stage(root, build), expected)
    assert limine.read_text() == original and not (root / stage.ESP_IMAGE).exists()

  mutate_case("replaced-kernel", "replaces the production kernel", lambda r: r.update(modified_sections_sha256={".linux": "c" * 64}))
  mutate_case("wrong-deltas", "declared upstream-model deltas", lambda r: r["deltas"].update(D1_modules_added=[]))
  mutate_case("removed-files", "removes production files", lambda r: r["initrd_manifest_diff"].update(removed=["init"]))
  mutate_case("missing-module", "exactly the four t2bce", lambda r: r["modules"].pop("t2bce_audio"))
  mutate_case("modified-flag", "offline-only", lambda r: r.update(installed=True))
  mutate_case("wrong-protocol", "Unexpected upstream-model provenance", lambda r: r.update(protocol="other"))
  mutate_case("stale-production", "differs from the image build base", lambda r: r.update(production_uki_sha256="d" * 64))

  root, build, limine, original, production = fixture(base / "group-readable")
  (build / C.BUILD_IMAGE).chmod(0o644)
  rejects(lambda: stage.stage(root, build), "private")

  root, build, limine, original, production = fixture(base / "stale-limine")
  limine.write_text(original.replace("#" + hashlib.blake2b(production.read_bytes()).hexdigest(), "#" + "e" * 128))
  rejects(lambda: stage.stage(root, build), "stale or ambiguous")

  root, build, limine, original, production = fixture(base / "unowned")
  limine.write_text(original + "\n/MBA-T2-upstream-model-deadbeefdeadbeef\nprotocol: efi\n")
  rejects(lambda: stage.stage(root, build), "unowned upstream-model entry")

  root, build, limine, original, production = fixture(base / "bad-snapshot")
  limine.write_text(original.replace("     ////linux-t2\n", "     ////linux-t2\n     default_entry: 1\n", 1))
  rejects(lambda: stage.stage(root, build), "")


with tempfile.TemporaryDirectory(prefix="t2-upstream-stage-flow-") as temporary:
  base = Path(temporary)
  root, build, limine, original, production = fixture(base / "flow")
  before_tree = tree_state(root)
  receipt = stage.stage(root, build)
  assert tree_state(root) == before_tree, "staging must not touch pair or product state"
  assert receipt["state"] == "staged" and receipt["entry_id"] == C.ENTRY_PREFIX + receipt["image_sha256"][:16]
  text = limine.read_text()
  assert text.startswith(original) and text.count(C.BEGIN) == 1 and text.count(C.END) == 1
  assert text.count("default_entry: 2") == 1 and "LoaderEntry" not in text
  assert ("path: boot():/EFI/Linux/" + C.ESP_IMAGE + "#" + hashlib.blake2b((build / C.BUILD_IMAGE).read_bytes()).hexdigest()) in text
  assert (root / stage.ESP_IMAGE).read_bytes() == (build / C.BUILD_IMAGE).read_bytes()
  assert (root / stage.ESP_IMAGE).stat().st_mode & 0o777 == 0o600
  assert (root / C.RECEIPT).stat().st_mode & 0o777 == 0o600
  stage.verify_staged(root, receipt)
  rejects(lambda: stage.stage(root, build), "already exists")

  # Evidence directories are preserved and validated.
  for name in C.STATE_NAMES:
    (root / C.STATE / name).mkdir(exist_ok=True)
  (root / C.STATE / "unexpected").write_text("x")
  rejects(lambda: stage.clear_rolled_back(root), "unknown files")
  (root / C.STATE / "unexpected").unlink()

  # Tampering is detected by every later action.
  good = limine.read_bytes()
  limine.write_bytes(good.replace(b"#" + receipt["image_blake2"].encode(), b"#" + b"f" * 128))
  rejects(lambda: stage.verify_staged(root, receipt), "unowned or modified")
  limine.write_bytes(good + b"timeout: 0\n")
  rejects(lambda: stage.verify_staged(root, receipt), "beyond the snapshot region")
  limine.write_bytes(good.replace(b"default_entry: 2", b"default_entry: 3"))
  rejects(lambda: stage.verify_staged(root, receipt), "not exactly entry 2")
  limine.write_bytes(good)
  (root / stage.ESP_IMAGE).write_bytes(b"swapped")
  rejects(lambda: stage.verify_staged(root, receipt), "image changed")
  (root / stage.ESP_IMAGE).write_bytes((build / C.BUILD_IMAGE).read_bytes())
  (root / stage.DEFAULT).write_bytes(efi_string("x"))
  rejects(lambda: stage.verify_staged(root, receipt), "ersistent EFI default")
  (root / stage.DEFAULT).unlink()
  production.write_bytes(production.read_bytes() + b"x")
  rejects(lambda: stage.verify_staged(root, receipt), "stale or ambiguous")
  production.write_bytes(production.read_bytes()[:-1])
  stage.verify_staged(root, receipt)

  # Snapshot churn is tolerated by verification.
  churned = good.replace(region_text(1).encode(), region_text(3, "c").encode())
  assert churned != good
  limine.write_bytes(churned)
  stage.verify_staged(root, receipt)
  limine.write_bytes(good)

  # First arm, from stock: needs advertisement.
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "not advertised")
  advertise(root, receipt)
  calls, synced = [], []
  armed = stage.arm(root, runner=bootctl_for(root, calls), sync=lambda: synced.append(True))
  assert armed["state"] == "armed" and calls == [receipt["entry_id"]] and synced
  assert stage.SINGLE.read_efi_string(root / stage.ONESHOT) == receipt["entry_id"]
  assert armed["armed_from_boot_id"] == BOOT_A
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "already present")
  rejects(lambda: stage.rollback(root), "Disarm")
  rejects(lambda: stage.clear_rolled_back(root), "Disarm")
  rejects(lambda: stage.mark_booted(root), "was not consumed")
  rejects(lambda: stage.arm_s4(root, 1, runner=bootctl_for(root)), "cannot be armed for S4")

  # Unknown one-shot is never cleared.
  (root / stage.ONESHOT).write_bytes(efi_string("Unrelated"))
  rejects(lambda: stage.disarm(root, runner=bootctl_for(root)), "unknown one-shot")
  (root / stage.ONESHOT).write_bytes(efi_string(receipt["entry_id"]))
  # Disarm is idempotent and leaves a re-armable state.
  assert stage.disarm(root, runner=bootctl_for(root))["state"] == "disarmed"
  assert stage.disarm(root, runner=bootctl_for(root))["state"] == "disarmed"
  assert not (root / stage.ONESHOT).exists()
  stage.arm(root, runner=bootctl_for(root))

  # The one-shot is consumed by a new boot of the exact entry.
  (root / stage.ONESHOT).unlink()
  rejects(lambda: stage.mark_booted(root), "not the exact upstream-model entry")
  set_boot(root, receipt["entry_id"], BOOT_A)
  rejects(lambda: stage.mark_booted(root), "new boot")
  set_boot(root, receipt["entry_id"], BOOT_B)
  booted = stage.mark_booted(root)
  assert booted["state"] == "booted" and booted["test_boot_id"] == BOOT_B

  # S4 arming is only from the test boot, in order, and per cycle.
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "healthy stock boot")
  rejects(lambda: stage.arm_s4(root, 0, runner=bootctl_for(root)), "1, 2 or 3")
  rejects(lambda: stage.arm_s4(root, 2, runner=bootctl_for(root)), "out of order")
  set_boot(root, receipt["entry_id"], BOOT_C)
  rejects(lambda: stage.arm_s4(root, 1, runner=bootctl_for(root)), "boot that verified")
  set_boot(root, C.STOCK_ENTRY, BOOT_B)
  rejects(lambda: stage.arm_s4(root, 1, runner=bootctl_for(root)), "exact upstream-model test boot")
  set_boot(root, receipt["entry_id"], BOOT_B)
  one = stage.arm_s4(root, 1, runner=bootctl_for(root))
  assert one["state"] == "s4-armed" and one["last_armed_cycle"] == 1
  assert stage.SINGLE.read_efi_string(root / stage.ONESHOT) == receipt["entry_id"]
  rejects(lambda: stage.arm_s4(root, 2, runner=bootctl_for(root)), "cannot be armed for S4")
  # S4 consumed the one-shot and the same boot returned.
  (root / stage.ONESHOT).unlink()
  assert stage.mark_booted(root)["state"] == "booted"
  set_boot(root, receipt["entry_id"], BOOT_C)
  (root / stage.ONESHOT).write_bytes(efi_string(receipt["entry_id"]))
  (root / stage.ONESHOT).unlink()
  set_boot(root, receipt["entry_id"], BOOT_B)
  two = stage.arm_s4(root, 2, runner=bootctl_for(root))
  assert two["last_armed_cycle"] == 2
  # A refused hibernate write lets the runner disarm and retry; the runner's guards decide whether a cycle was attempted.
  assert stage.disarm(root, runner=bootctl_for(root))["state"] == "disarmed"
  rejects(lambda: stage.arm_s4(root, 4, runner=bootctl_for(root)), "1, 2 or 3")
  assert stage.arm_s4(root, 2, runner=bootctl_for(root))["last_armed_cycle"] == 2
  stage.disarm(root, runner=bootctl_for(root))
  assert stage.arm_s4(root, 3, runner=bootctl_for(root))["last_armed_cycle"] == 3
  stage.disarm(root, runner=bootctl_for(root))
  rejects(lambda: stage.arm_s4(root, 4, runner=bootctl_for(root)), "1, 2 or 3")

  # A terminal image hash cannot be armed again and stays terminal.
  assert stage.mark_terminal(root, receipt["image_sha256"], "S4 cycle failed")
  assert not stage.mark_terminal(root, receipt["image_sha256"], "again")
  rejects(lambda: stage.arm_s4(root, 3, runner=bootctl_for(root)), "rejected, consumed or terminal")
  set_boot(root, C.STOCK_ENTRY, BOOT_C)
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "rejected, consumed or terminal")

  # Rollback from the stock boot removes exactly the owned block, preserving snapshot churn.
  limine.write_bytes(churned)
  rolled = stage.rollback(root)
  assert rolled["state"] == "rolled-back"
  assert not (root / stage.ESP_IMAGE).exists()
  assert limine.read_bytes() == churned.replace(stage.entry_block(receipt), b"")
  assert stage.POLICY.limine_canonical(limine.read_bytes()) == stage.POLICY.limine_canonical(original.encode())
  assert C.BEGIN not in limine.read_text()
  assert stage.rollback(root)["state"] == "rolled-back"
  cleared = stage.clear_rolled_back(root)
  assert cleared["state"] == "cleared" and not (root / C.RECEIPT).exists() and not (root / C.BACKUP).exists()
  assert (root / C.TERMINAL / (receipt["image_sha256"] + ".json")).exists() and (root / C.ATTEMPTS).is_dir()
  assert stage.clear_rolled_back(root)["state"] == "cleared"
  assert tree_state(root) == before_tree
  # A terminal hash is never staged again.
  rejects(lambda: stage.stage(root, build), "rejected, consumed or terminal")


with tempfile.TemporaryDirectory(prefix="t2-upstream-stage-crash-") as temporary:
  base = Path(temporary)

  # Crash after the image was written and before Limine was updated: automatic recovery.
  root, build, limine, original, production = fixture(base / "stage-crash")
  real_write = stage.atomic_write

  def failing_limine(path, data, mode):
    if path.name == "limine.conf":
      raise OSError("simulated power loss before Limine update")
    real_write(path, data, mode)

  stage.atomic_write = failing_limine
  try:
    try:
      stage.stage(root, build)
    except OSError as error:
      assert "simulated" in str(error)
    else:
      raise AssertionError("failed staging accepted")
  finally:
    stage.atomic_write = real_write
  assert limine.read_text() == original and not (root / stage.ESP_IMAGE).exists()
  failed = stage.load_receipt(root)
  assert failed["state"] == "stage-failed-recovered"
  rejects(lambda: stage.stage(root, build), "already exists")
  assert stage.rollback(root)["state"] == "rolled-back"
  assert stage.clear_rolled_back(root)["state"] == "cleared"
  assert stage.stage(root, build)["state"] == "staged"

  # Crash while writing the receipt itself, before any ESP change: the unpublished backup is cleaned.
  root, build, limine, original, production = fixture(base / "receipt-crash")

  def failing_receipt(path, data, mode):
    if path.name == "receipt.json":
      raise OSError("simulated receipt failure")
    real_write(path, data, mode)

  stage.atomic_write = failing_receipt
  try:
    try:
      stage.stage(root, build)
    except OSError:
      pass
    else:
      raise AssertionError("failed receipt accepted")
  finally:
    stage.atomic_write = real_write
  assert not (root / C.BACKUP).exists() and not (root / stage.ESP_IMAGE).exists() and limine.read_text() == original

  # Crash between the two arm writes: the arming state still disarms.
  root, build, limine, original, production = fixture(base / "arm-crash")
  receipt = stage.stage(root, build)
  advertise(root, receipt)

  def dying_bootctl(arguments, check):
    (root / stage.ONESHOT).write_bytes(efi_string(arguments[2]))
    raise KeyboardInterrupt

  try:
    stage.arm(root, runner=dying_bootctl)
  except KeyboardInterrupt:
    pass
  assert stage.load_receipt(root)["state"] == "arming"
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "cannot be armed from state arming")
  assert stage.disarm(root, runner=bootctl_for(root))["state"] == "disarmed"
  assert not (root / stage.ONESHOT).exists()
  # Crash before the one-shot was written is also recoverable.
  stage.arm(root, runner=bootctl_for(root))
  assert stage.load_receipt(root)["state"] == "armed"
  (root / stage.ONESHOT).unlink()

  # Rollback resumes after a crash between block removal and image removal.
  real_remove_image = stage.remove_image

  def failing_image(root_argument, receipt_argument):
    raise OSError("simulated crash before image removal")

  stage.remove_image = failing_image
  try:
    try:
      stage.rollback(root)
    except OSError:
      pass
    else:
      raise AssertionError("failed rollback accepted")
  finally:
    stage.remove_image = real_remove_image
  assert stage.load_receipt(root)["state"] == "rolling-back"
  assert C.BEGIN not in limine.read_text() and (root / stage.ESP_IMAGE).exists()
  assert stage.rollback(root)["state"] == "rolled-back"
  assert not (root / stage.ESP_IMAGE).exists()
  assert limine.read_text() == original

  # Rollback refuses an unknown image and an unknown Limine text; it never guesses.
  root, build, limine, original, production = fixture(base / "rollback-unknown")
  receipt = stage.stage(root, build)
  (root / stage.ESP_IMAGE).write_bytes(b"foreign")
  rejects(lambda: stage.rollback(root), "unknown upstream-model image")
  (root / stage.ESP_IMAGE).write_bytes((build / C.BUILD_IMAGE).read_bytes())
  limine.write_text(limine.read_text() + "timeout: 0\n")
  rejects(lambda: stage.rollback(root), "beyond the snapshot region")
  assert stage.load_receipt(root)["state"] == "rolling-back"

  # Rollback and clear need the stock boot.
  root, build, limine, original, production = fixture(base / "rollback-boot")
  receipt = stage.stage(root, build)
  set_boot(root, receipt["entry_id"], BOOT_B)
  rejects(lambda: stage.rollback(root), "stock boot")
  set_boot(root, C.STOCK_ENTRY, BOOT_B)
  stage.rollback(root)
  set_boot(root, receipt["entry_id"], BOOT_B)
  rejects(lambda: stage.clear_rolled_back(root), "stock boot")

  # Clear refuses an un-rolled-back transaction.
  root, build, limine, original, production = fixture(base / "clear-early")
  stage.stage(root, build)
  rejects(lambda: stage.clear_rolled_back(root), "rolled back before clearing")

  # Arming refuses once maintenance ends (product reactivated), and a missing kernel policy.
  root, build, limine, original, production = fixture(base / "arm-active")
  receipt = stage.stage(root, build)
  advertise(root, receipt)
  (root / stage.MAINTENANCE).unlink()
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "not in package maintenance")
  (root / stage.MAINTENANCE).write_text("pending\n")
  receipt.pop("kernel_policy")
  stage.save_receipt(root, receipt)
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "production-kernel boot policy")
  assert not (root / stage.ONESHOT).exists()

with tempfile.TemporaryDirectory(prefix="t2-upstream-stage-audit-") as temporary:
  base = Path(temporary)

  # Churn between the image write and the Limine write is preserved, not overwritten.
  root, build, limine, original, production = fixture(base / "churn")
  real_write = stage.atomic_write
  churned_text = original.replace(region_text(1), region_text(4, "d"))
  assert churned_text != original

  def churning(path, data, mode):
    real_write(path, data, mode)
    if path.name == C.ESP_IMAGE:
      limine.write_text(churned_text)

  stage.atomic_write = churning
  try:
    receipt = stage.stage(root, build)
  finally:
    stage.atomic_write = real_write
  assert limine.read_text() == churned_text + stage.entry_block(receipt).decode()
  stage.verify_staged(root, receipt)
  # Churn that is not a snapshot region aborts and recovers without losing the foreign edit.
  root, build, limine, original, production = fixture(base / "foreign-churn")

  def foreign(path, data, mode):
    real_write(path, data, mode)
    if path.name == C.ESP_IMAGE:
      limine.write_text(original + "timeout: 0\n")

  stage.atomic_write = foreign
  try:
    rejects(lambda: stage.stage(root, build), "while staging")
  finally:
    stage.atomic_write = real_write
  assert limine.read_text() == original + "timeout: 0\n" and not (root / stage.ESP_IMAGE).exists()
  assert stage.load_receipt(root)["state"] == "stage-failed-recovered"

  # Locks: a held db.lck or physical lock refuses, and our own db.lck is always released.
  root, build, limine, original, production = fixture(base / "locks")
  (root / stage.DB_LOCK).write_text("held")
  rejects(lambda: stage.stage(root, build), "db.lck is held")
  assert (root / stage.DB_LOCK).read_text() == "held"
  (root / stage.DB_LOCK).unlink()
  import fcntl
  descriptor = os.open(root / stage.PHYSICAL_LOCK, os.O_RDONLY)
  fcntl.flock(descriptor, fcntl.LOCK_EX)
  rejects(lambda: stage.stage(root, build), "physical lock")
  assert not (root / stage.DB_LOCK).exists() and not (root / C.RECEIPT).exists()
  fcntl.flock(descriptor, fcntl.LOCK_UN)
  os.close(descriptor)
  (root / stage.PHYSICAL_LOCK).unlink()
  rejects(lambda: stage.stage(root, build), "physical cycle lock is missing")
  (root / stage.PHYSICAL_LOCK).write_text("")
  seen = []
  real_judge = stage.judge_limine
  stage.judge_limine = lambda *a: (seen.append((root / stage.DB_LOCK).exists()), real_judge(*a))[1]
  try:
    receipt = stage.stage(root, build)
  finally:
    stage.judge_limine = real_judge
  assert seen and all(seen) and not (root / stage.DB_LOCK).exists()
  # A signal inside the lock unwinds through the release.
  import signal

  def killed(*_a):
    os.kill(os.getpid(), signal.SIGTERM)

  advertise(root, receipt)
  real_verify = stage.verify_staged
  stage.verify_staged = lambda *a: (killed(), real_verify(*a))[1]
  try:
    try:
      stage.arm(root, runner=bootctl_for(root))
    except SystemExit as error:
      assert error.code == 128 + signal.SIGTERM
    else:
      raise AssertionError("signal ignored")
  finally:
    stage.verify_staged = real_verify
  assert not (root / stage.DB_LOCK).exists()
  assert stage.load_receipt(root)["state"] == "staged"

  # Pair interplay: steady source-arming is allowed, transient pair states refuse, a changed pair receipt blocks arming.
  for state, allowed in (("source-arming", True), ("staged", True), ("rolled-back", True), ("restore-arming", False), ("preparing", False), ("rolling-back", False)):
    root, build, limine, original, production = fixture(base / ("pair-" + state))
    (root / stage.PAIR_STATE / "receipt.json").write_text(json.dumps({"state": state, "images": {"source": {"sha256": "5" * 64}}}))
    if allowed:
      assert stage.stage(root, build)["pair_receipt_sha256"] == sha((root / stage.PAIR_STATE / "receipt.json").read_bytes())
    else:
      rejects(lambda: stage.stage(root, build), "pair transaction is pending")
      assert limine.read_text() == original
  root, build, limine, original, production = fixture(base / "pair-changed")
  receipt = stage.stage(root, build)
  advertise(root, receipt)
  assert "# BEGIN omarchy T2 hibernation pair" in limine.read_text()
  (root / stage.PAIR_STATE / "receipt.json").write_text(json.dumps({"state": "rolled-back"}))
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "pair receipt changed")
  assert not (root / stage.ONESHOT).exists()

  # ESP space and build parents.
  root, build, limine, original, production = fixture(base / "esp-full")
  real_statvfs = os.statvfs
  os.statvfs = lambda path: type("V", (), {"f_bavail": 1, "f_frsize": 4096})()
  try:
    rejects(lambda: stage.stage(root, build), "free space")
  finally:
    os.statvfs = real_statvfs
  assert not (root / stage.ESP_IMAGE).exists() and not (root / C.RECEIPT).exists()
  root, build, limine, original, production = fixture(base / "open-parent")
  build.parent.chmod(0o777)
  try:
    rejects(lambda: stage.stage(root, build), "untrusted parent")
  finally:
    build.parent.chmod(0o755)

  # F3: boot arming from stock is refused once an S4 cycle was armed, unless it was disarmed.
  root, build, limine, original, production = fixture(base / "f3")
  receipt = stage.stage(root, build)
  advertise(root, receipt)
  stage.arm(root, runner=bootctl_for(root))
  (root / stage.ONESHOT).unlink()
  set_boot(root, receipt["entry_id"], BOOT_B)
  stage.mark_booted(root)
  stage.arm_s4(root, 1, runner=bootctl_for(root))
  (root / stage.ONESHOT).unlink()
  set_boot(root, C.STOCK_ENTRY, BOOT_C)
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "cannot be armed from state s4-armed")
  assert stage.load_receipt(root)["state"] == "s4-armed"
  # F4: same-cycle re-arm only from disarmed, never from booted.
  set_boot(root, receipt["entry_id"], BOOT_B)
  stage.mark_booted(root)
  rejects(lambda: stage.arm_s4(root, 1, runner=bootctl_for(root)), "out of order")
  assert stage.arm_s4(root, 2, runner=bootctl_for(root))["last_armed_cycle"] == 2
  stage.disarm(root, runner=bootctl_for(root))
  assert stage.arm_s4(root, 2, runner=bootctl_for(root))["last_armed_cycle"] == 2

  # F5: an interrupted arm (state arming) is confirmed by mark_booted when purpose, boot and entry match.
  root, build, limine, original, production = fixture(base / "f5-boot")
  receipt = stage.stage(root, build)
  advertise(root, receipt)

  def dying(arguments, check):
    (root / stage.ONESHOT).write_bytes(efi_string(arguments[2]))
    raise KeyboardInterrupt

  try:
    stage.arm(root, runner=dying)
  except KeyboardInterrupt:
    pass
  assert stage.load_receipt(root)["state"] == "arming"
  (root / stage.ONESHOT).unlink()
  set_boot(root, receipt["entry_id"], BOOT_A)
  rejects(lambda: stage.mark_booted(root), "new boot")
  set_boot(root, receipt["entry_id"], BOOT_B)
  booted = stage.mark_booted(root)
  assert booted["state"] == "booted" and booted["test_boot_id"] == BOOT_B and "arming" not in booted
  try:
    stage.arm_s4(root, 1, runner=dying)
  except KeyboardInterrupt:
    pass
  assert stage.load_receipt(root)["state"] == "arming"
  (root / stage.ONESHOT).unlink()
  set_boot(root, receipt["entry_id"], BOOT_C)
  rejects(lambda: stage.mark_booted(root), "differs from the verified test boot")
  set_boot(root, receipt["entry_id"], BOOT_B)
  assert stage.mark_booted(root)["state"] == "booted"

  # R1: a pair receipt change while armed must not stop disarm or mark_booted; arming still refuses.
  root, build, limine, original, production = fixture(base / "r1")
  receipt = stage.stage(root, build)
  advertise(root, receipt)
  stage.arm(root, runner=bootctl_for(root))
  (root / stage.PAIR_STATE / "receipt.json").write_text(json.dumps({"state": "rolled-back"}))
  assert stage.disarm(root, runner=bootctl_for(root))["state"] == "disarmed"
  assert not (root / stage.ONESHOT).exists()
  rejects(lambda: stage.arm(root, runner=bootctl_for(root)), "pair receipt changed")
  rejects(lambda: stage.verify_staged(root, receipt), "pair receipt changed")
  stage.verify_staged(root, receipt, pair=False)
  root, build, limine, original, production = fixture(base / "r1-booted")
  receipt = stage.stage(root, build)
  advertise(root, receipt)
  stage.arm(root, runner=bootctl_for(root))
  (root / stage.ONESHOT).unlink()
  set_boot(root, receipt["entry_id"], BOOT_B)
  (root / stage.PAIR_STATE / "receipt.json").write_text(json.dumps({"state": "rolled-back"}))
  assert stage.mark_booted(root)["state"] == "booted"

print("PASS: upstream-model stager locks, re-reads Limine before writing and enforces arm ordering")
