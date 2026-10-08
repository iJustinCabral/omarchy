#!/usr/bin/python3
"""Transactionally stage one private upstream-model UKI with stock fallback.

A single hash-bound Limine entry (MBA-T2-upstream-model-<16 hex>) is appended to the
Limine configuration while the T2 hibernation product is in inactive package maintenance.
Staging does not arm a boot. Arming always sets LoaderEntryOneShot (never a persistent
default): from the stock boot for the first boot of the image, and from the test boot
before each S4 cycle. The tool owns only its own state directory and its own block in
Limine; it never touches the pair receipt, pair custody or any product state, and it
never enters a power transition.
"""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("upstream_model_common", HERE / "common.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)
SINGLE = C.import_path("upstream_model_single_boot_stager", C.EXPERIMENTS / "stage-hibernation-candidate-boot.py")
POLICY = C.import_path("upstream_model_boot_policy", C.HIBERNATE / "boot_policy.py")

LIMINE = SINGLE.LIMINE
ONESHOT = SINGLE.ONESHOT
DEFAULT = SINGLE.DEFAULT
SELECTED = SINGLE.SELECTED
ENTRIES = SINGLE.ENTRIES
BOOT_ID = Path("proc/sys/kernel/random/boot_id")
ESP_IMAGE = Path("boot/EFI/Linux") / C.ESP_IMAGE
PRODUCT_STATE = Path("var/lib/omarchy/t2-hibernate-product")
MAINTENANCE = PRODUCT_STATE / "package-maintenance.pending"
PRODUCT_ACTIVE = (
  PRODUCT_STATE / "boot-policy.json",
  PRODUCT_STATE / "source-default-activation.pending",
  PRODUCT_STATE / "source-default-deactivation.pending",
  PRODUCT_STATE / "runtime-upgrade.pending",
  PRODUCT_STATE / ".runtime-pending",
  Path("etc/omarchy/t2-hibernate-product.enabled"),
)
PAIR_STATE = Path("var/lib/omarchy-t2-hibernation-pair")
PAIR_EVIDENCE = (PAIR_STATE / "test-resume-vectors", PAIR_STATE / "s4-vectors",
                 Path("var/lib/omarchy-t2-hibernation-pair-retired"), Path("var/lib/omarchy-t2-hibernation-candidate"))
PHYSICAL_LOCK = Path("var/lib/omarchy/t2-hibernate-trial/physical-cycle.lock")
DB_LOCK = Path("var/lib/pacman/db.lck")
PAIR_PENDING_STATES = ("preparing", "restore-arming", "rolling-back", "stage-failed-recovered")
ESP_HEADROOM = 16 * 1024 * 1024
STATE_FILES = ("receipt.json", "limine.conf.before", "runner.lock")
SCHEMA = "omarchy-t2-upstream-model-stage-v1"
MAX_PROVENANCE = 4 * 1024 * 1024
ARMED = ("armed", "s4-armed")


def rooted(root, relative):
  return SINGLE.rooted(Path(root), relative)


def atomic_write(path, data, mode):
  SINGLE.atomic_write(path, data, mode)


def fsync_directory(path):
  SINGLE.fsync_directory(path)


def owner_of(root):
  return 0 if Path(root).resolve() == Path("/") else os.geteuid()


def current_boot_id(root):
  value = rooted(root, BOOT_ID).read_text().strip()
  if C.UUID.fullmatch(value) is None:
    raise ValueError("Current boot ID is malformed")
  return value


def selected_entry(root):
  path = rooted(root, SELECTED)
  if not path.is_file():
    raise ValueError("LoaderEntrySelected is absent")
  return SINGLE.read_efi_string(path)


def present(root, relative):
  return os.path.lexists(rooted(root, relative))


# ---- Machine state -----------------------------------------------------------------

def require_maintenance(root):
  """Product must be in inactive package maintenance: the marker exists and nothing is active."""
  marker = rooted(root, MAINTENANCE)
  if marker.is_symlink() or not marker.is_file():
    raise ValueError("T2 hibernation product is not in package maintenance; refusing")
  for relative in PRODUCT_ACTIVE:
    if present(root, relative):
      raise ValueError("T2 hibernation product is not inactive: " + relative.name)
  for relative in (DEFAULT,):
    if present(root, relative):
      raise ValueError("A persistent EFI default would weaken stock fallback")


def rejected_hashes(root):
  """Static rejected images plus every image hash the pair tooling recorded or consumed."""
  result = set(C.REJECTED_IMAGE_SHA256)
  try:
    receipt = json.loads(rooted(root, PAIR_STATE / "receipt.json").read_text())
    for metadata in receipt.get("images", {}).values():
      result.add(metadata.get("sha256"))
  except (FileNotFoundError, NotADirectoryError, json.JSONDecodeError, AttributeError):
    pass
  for relative in PAIR_EVIDENCE:
    directory = rooted(root, relative)
    if directory.is_dir() and not directory.is_symlink():
      result.update(item.name for item in directory.iterdir() if C.SHA256.fullmatch(item.name))
  terminal = rooted(root, C.TERMINAL)
  if terminal.is_dir() and not terminal.is_symlink():
    result.update(item.name.removesuffix(".json") for item in terminal.iterdir())
  return {value for value in result if isinstance(value, str)}


def reject_image(root, image_sha256):
  if image_sha256 in rejected_hashes(root):
    raise ValueError("Image hash is rejected, consumed or terminal and must not be staged or armed: " + image_sha256)


def is_terminal(root, image_sha256):
  return rooted(root, C.TERMINAL / (image_sha256 + ".json")).exists()


def mark_terminal(root, image_sha256, reason):
  """Durably mark an image hash terminal (exclusive create; never removed by this tool).

  The runner's reclassify archives a userspace misclassification by renaming the marker to
  <sha>.reclassified-<time>.json. This function still never unlinks it.
  """
  path = rooted(root, C.TERMINAL / (image_sha256 + ".json"))
  path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
  data = (json.dumps({"image_sha256": image_sha256, "reason": reason}, indent=2, sort_keys=True) + "\n").encode()
  try:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  except FileExistsError:
    return False
  with os.fdopen(descriptor, "wb") as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
  fsync_directory(path.parent)
  return True


@contextmanager
def locks(root):
  """The exclusion the product transitions use: pacman db.lck (exclusive create) plus the physical cycle lock."""
  lock = rooted(root, PHYSICAL_LOCK)
  if lock.is_symlink() or not lock.is_file():
    raise ValueError("Fixed physical cycle lock is missing")
  db = rooted(root, DB_LOCK)
  try:
    db_fd = os.open(db, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  except FileExistsError:
    raise ValueError("pacman db.lck is held; retry after the package transaction ends") from None
  physical, previous = None, {}

  def terminate(signum, _frame):
    raise SystemExit(128 + signum)

  try:
    # Terminating signals unwind through the finally so that only the db.lck created here is released.
    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
      try:
        previous[getattr(signal, name)] = signal.signal(getattr(signal, name), terminate)
      except ValueError:
        break
    physical = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
      fcntl.flock(physical, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
      raise ValueError("A hibernation cycle holds the physical lock") from None
    yield
  finally:
    for number, handler in previous.items():
      signal.signal(number, handler)
    if physical is not None:
      os.close(physical)
    held = os.fstat(db_fd)
    os.close(db_fd)
    current = db.lstat()
    if (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino):
      db.unlink()
      fsync_directory(db.parent)


def pair_receipt_sha256(root):
  path = rooted(root, PAIR_STATE / "receipt.json")
  return C.sha256(path.read_bytes()) if path.is_file() else None


def require_pair_quiet(root):
  """A pair transaction in a transient state means another transition is mid-flight; steady source-arming is normal."""
  path = rooted(root, PAIR_STATE / "receipt.json")
  if path.is_file():
    try:
      state = json.loads(path.read_text()).get("state")
    except json.JSONDecodeError:
      raise ValueError("Pair receipt is malformed; refusing") from None
    if state in PAIR_PENDING_STATES:
      raise ValueError("A pair transaction is pending (" + str(state) + "); finish it before using the upstream model")


def require_esp_space(root, size):
  free = os.statvfs(rooted(root, ESP_IMAGE).parent)
  if free.f_bavail * free.f_frsize < size + ESP_HEADROOM:
    raise ValueError("Not enough free space on the ESP for the image")


def require_private_parents(directory, owner):
  for parent in Path(directory).resolve().parents:
    metadata = parent.stat()
    if metadata.st_uid not in (0, owner) or (metadata.st_mode & 0o022 and not metadata.st_mode & 0o1000):
      raise ValueError("Build input has an untrusted parent directory: " + str(parent))


# ---- Build input -------------------------------------------------------------------

def pe_sections(data):
  """PE section table as {name: (virtual size, characteristics, raw bytes)}; no subprocess, no padding."""
  try:
    pe = int.from_bytes(data[0x3c:0x40], "little")
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0":
      raise ValueError("not a PE image")
    count = int.from_bytes(data[pe + 6:pe + 8], "little")
    table = pe + 24 + int.from_bytes(data[pe + 20:pe + 22], "little")
    result = {}
    for index in range(count):
      entry = data[table + 40 * index:table + 40 * (index + 1)]
      if len(entry) != 40:
        raise ValueError("truncated section table")
      name = entry[:8].rstrip(b"\0").decode("ascii")
      virtual = int.from_bytes(entry[8:12], "little")
      size = int.from_bytes(entry[16:20], "little")
      offset = int.from_bytes(entry[20:24], "little")
      raw = data[offset:offset + size]
      if len(raw) != size or name in result:
        raise ValueError("malformed section: " + name)
      result[name] = (virtual, int.from_bytes(entry[36:40], "little"), raw)
    return result
  except (IndexError, UnicodeDecodeError) as error:
    raise ValueError("UKI is not a readable PE image") from error


def verify_production_sections(production, image_data, expected_production_hash):
  """.linux, .cmdline and every other non-.initrd section equal production byte-for-byte."""
  production_data = Path(production).read_bytes()
  if hashlib.sha256(production_data).hexdigest() != expected_production_hash:
    raise ValueError("Production UKI changed before upstream-model staging")
  before, after = pe_sections(production_data), pe_sections(image_data)
  if set(before) != set(after) or not {".linux", ".cmdline", ".initrd"} <= set(before):
    raise ValueError("Upstream-model UKI section set differs from production")
  for name in before:
    if name == ".initrd":
      continue
    if name in (".linux", ".cmdline") and not before[name][2].rstrip(b"\0"):
      raise ValueError("Production UKI lacks a nonempty " + name + " section")
    if before[name] != after[name]:
      raise ValueError("Upstream-model UKI " + name + " differs from production; physical root boot is unqualified")


def load_build(root, directory):
  directory = Path(directory)
  owner = owner_of(root)
  require_private_parents(directory, owner)
  for path in (directory, directory / C.BUILD_IMAGE, directory / C.BUILD_PROVENANCE):
    if path.is_symlink() or not path.exists():
      raise ValueError("Build input is missing or symlinked: " + str(path))
    metadata = path.lstat()
    if metadata.st_uid != owner or metadata.st_mode & 0o077:
      raise ValueError("Build input must be owned by the stager and private: " + str(path))
  report_data = (directory / C.BUILD_PROVENANCE).read_bytes()
  if len(report_data) > MAX_PROVENANCE:
    raise ValueError("Oversized build provenance")
  provenance = json.loads(report_data)
  image_data = (directory / C.BUILD_IMAGE).read_bytes()
  if not isinstance(provenance, dict) or provenance.get("candidate") != C.CANDIDATE or provenance.get("protocol") != C.PROTOCOL:
    raise ValueError("Unexpected upstream-model provenance")
  if provenance.get("candidate_uki_sha256") != hashlib.sha256(image_data).hexdigest():
    raise ValueError("Upstream-model UKI hash mismatch")
  for key in ("production_modified", "installed", "boot_entry_created", "hardware_qualified"):
    if provenance.get(key) is not False:
      raise ValueError("Build is not in offline-only state: " + key)
  unchanged = provenance.get("unchanged_production_sections_sha256")
  if provenance.get("modified_sections_sha256") is not None or not isinstance(unchanged, dict) or ".linux" not in unchanged or ".cmdline" not in unchanged:
    raise ValueError("Image replaces the production kernel; physical root boot is unqualified")
  if not provenance.get("experiment_id"):
    raise ValueError("Image lacks an experiment ID")
  deltas = provenance.get("deltas")
  if (not isinstance(deltas, dict) or deltas.get("D1_modules_added") != ["t2bce_audio"] or
      deltas.get("D2_initramfs_blacklist") != list(C.BLACKLISTED_MODULES) or deltas.get("build_hook") != C.HOOK):
    raise ValueError("Image does not carry exactly the declared upstream-model deltas")
  diff = provenance.get("initrd_manifest_diff")
  if (not isinstance(diff, dict) or not isinstance(diff.get("removed"), list) or not isinstance(diff.get("added"), list)
      or not isinstance(diff.get("audio_dependencies"), list)
      or not isinstance(provenance.get("kernel_release"), str)):
    raise ValueError("Image initramfs manifest diff is missing or malformed")
  if any(not isinstance(item, str) for key in ("removed", "added", "audio_dependencies") for item in diff[key]):
    raise ValueError("Image initramfs manifest diff entries must all be strings")
  problems = C.delta_problems(diff["removed"], diff["added"], provenance["kernel_release"], diff["audio_dependencies"])
  if problems:
    raise ValueError("Image initramfs manifest diff removes or adds production files beyond the declared deltas: " + "; ".join(problems[:6]))
  modules = provenance.get("modules")
  if not isinstance(modules, dict) or set(modules) != set(C.T2BCE_MODULES):
    raise ValueError("Image does not pin exactly the four t2bce modules")
  for name, metadata in modules.items():
    if C.SHA256.fullmatch(str(metadata.get("sha256"))) is None or not metadata.get("srcversion"):
      raise ValueError("Image module pin is incomplete: " + name)
  return image_data, provenance, hashlib.sha256(report_data).hexdigest()


# ---- Limine ------------------------------------------------------------------------

def read_limine(root):
  path = rooted(root, LIMINE)
  with path.open("rb") as stream:
    data = stream.read(POLICY.MAX_BYTES + 1)
  if len(data) > POLICY.MAX_BYTES:
    raise ValueError("Oversized Limine configuration")
  return data


def production_path_line(root):
  production = rooted(root, Path("boot/EFI/Linux") / C.PRODUCTION_IMAGE)
  return production, "path: boot():/EFI/Linux/" + C.PRODUCTION_IMAGE + "#" + SINGLE.blake2(production)


def validate_limine_production(root, production_sha256):
  """Stock default 2 and a coherent production path line; returns the current bytes."""
  text = read_limine(root).decode()
  production, line = production_path_line(root)
  if len(re.findall(r"^default_entry:\s*2\s*$", text, re.M)) != 1:
    raise ValueError("Production Limine default is not exactly entry 2")
  if text.count(line) != 1:
    raise ValueError("Production Limine image hash is stale or ambiguous")
  if SINGLE.digest(production) != production_sha256:
    raise ValueError("Production UKI differs from the image build base")
  return text.encode()


def entry_block(receipt):
  identifier = C.entry_id(receipt["image_sha256"])
  if receipt["entry_id"] != identifier:
    raise ValueError("Receipt entry is not bound to the UKI hash")
  return (
    "\n" + C.BEGIN + "\n"
    "/" + identifier + "\n"
    "comment: One-shot upstream-model test; stock remains the explicit default\n"
    "protocol: efi\n"
    "path: boot():/EFI/Linux/" + C.ESP_IMAGE + "#" + receipt["image_blake2"] + "\n"
    + C.END + "\n"
  ).encode()


def judge_limine(receipt, current, backup):
  """(current bytes without our block, block present).

  Only the limine-snapper-sync snapshot region may differ from the pre-staging backup
  (boot_policy.limine_canonical, strict and fail-closed). The block is removed from the
  current bytes, never the backup restored over them, so snapshot churn is preserved.
  """
  if C.sha256(backup) != receipt["original_limine_sha256"]:
    raise ValueError("Upstream-model Limine backup changed")
  block = entry_block(receipt)
  count = current.count(block)
  if count > 1:
    raise ValueError("Managed upstream-model block is duplicated")
  remainder = current.replace(block, b"") if count else current
  for marker in (C.BEGIN, C.END, "/" + C.ENTRY_PREFIX, C.ESP_IMAGE):
    if marker.encode() in remainder:
      raise ValueError("Limine holds unowned or modified upstream-model text: " + marker)
  if POLICY.limine_canonical(remainder) != POLICY.limine_canonical(backup):
    raise ValueError("Limine changed beyond the snapshot region and the owned block")
  return remainder, bool(count)


# ---- Receipt and verification ------------------------------------------------------

def save_receipt(root, receipt):
  atomic_write(rooted(root, C.RECEIPT), (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def load_receipt(root):
  path = rooted(root, C.RECEIPT)
  if not path.is_file():
    raise ValueError("Upstream-model staging receipt is missing")
  data = json.loads(path.read_text())
  if not isinstance(data, dict) or data.get("schema") != SCHEMA:
    raise ValueError("Upstream-model staging receipt is malformed")
  return data


def verify_staged(root, receipt, pair=True):
  image = rooted(root, ESP_IMAGE)
  if not image.is_file() or SINGLE.digest(image) != receipt["image_sha256"] or SINGLE.blake2(image) != receipt["image_blake2"]:
    raise ValueError("Staged upstream-model image changed")
  backup = rooted(root, C.BACKUP)
  if not backup.is_file():
    raise ValueError("Upstream-model Limine backup is missing")
  current = validate_limine_production(root, receipt["production_uki_sha256"])
  _remainder, found = judge_limine(receipt, current, backup.read_bytes())
  if not found:
    raise ValueError("Managed upstream-model block is missing")
  text = current.decode()
  if text.count("/" + receipt["entry_id"] + "\n") != 1:
    raise ValueError("Hash-bound upstream-model entry is missing or duplicated")
  if text.count("path: boot():/EFI/Linux/" + C.ESP_IMAGE + "#" + receipt["image_blake2"]) != 1:
    raise ValueError("Upstream-model Limine hash is stale or ambiguous")
  if present(root, DEFAULT):
    raise ValueError("Persistent EFI default would weaken stock fallback")
  if pair and receipt.get("pair_receipt_sha256") != pair_receipt_sha256(root):
    raise ValueError("The pair receipt changed since staging; roll back the upstream model before any pair retire, rollback or rebind")


def verify_recovered(root, receipt):
  backup = rooted(root, C.BACKUP)
  if not backup.is_file():
    raise ValueError("Upstream-model Limine backup is missing")
  _remainder, found = judge_limine(receipt, read_limine(root), backup.read_bytes())
  if found:
    raise ValueError("Managed block remains in Limine")
  if present(root, ESP_IMAGE):
    raise ValueError("Upstream-model image remains on the ESP")


def validate_state(state, extra=()):
  if not state.is_dir() or state.is_symlink():
    raise ValueError("Upstream-model state is not a real directory")
  allowed = set(C.STATE_NAMES) | set(extra)
  unexpected = sorted(path.name for path in state.iterdir() if path.name not in allowed)
  if unexpected:
    raise ValueError("Upstream-model state contains unknown files: " + ", ".join(unexpected))
  for name in C.STATE_NAMES:
    path = state / name
    if path.is_symlink() or (path.exists() and not path.is_dir()):
      raise ValueError("Upstream-model evidence is not a real directory: " + name)


def remove_limine_block(root, receipt):
  limine = rooted(root, LIMINE)
  current = read_limine(root)
  if C.BEGIN.encode() not in current:
    return  # nothing of ours to remove; foreign edits are not ours to judge here
  remainder, found = judge_limine(receipt, current, rooted(root, C.BACKUP).read_bytes())
  if found:
    atomic_write(limine, remainder, 0o600)


def remove_image(root, receipt):
  image = rooted(root, ESP_IMAGE)
  if image.exists():
    if SINGLE.digest(image) != receipt["image_sha256"]:
      raise ValueError("Refusing to remove an unknown upstream-model image")
    image.unlink()
    fsync_directory(image.parent)


def recover_failed_stage(root, receipt, failure):
  remove_limine_block(root, receipt)
  remove_image(root, receipt)
  receipt["state"] = "stage-failed-recovered"
  receipt["failure"] = str(failure)
  save_receipt(root, receipt)
  verify_recovered(root, receipt)


def clean_unpublished_stage(root):
  if present(root, ESP_IMAGE):
    raise ValueError("Cannot clean unpublished staging: image exists")
  backup = rooted(root, C.BACKUP)
  if backup.exists():
    backup.unlink()
    fsync_directory(backup.parent)


def stage(root, build_directory):
  with locks(root):
    return _stage(root, build_directory)


def _stage(root, build_directory):
  state = rooted(root, C.STATE)
  if state.exists():
    validate_state(state, STATE_FILES)
  if present(root, C.RECEIPT) or present(root, C.BACKUP) or present(root, ESP_IMAGE):
    raise ValueError("An upstream-model transaction already exists")
  require_maintenance(root)
  require_pair_quiet(root)
  image_data, provenance, provenance_sha256 = load_build(root, build_directory)
  image_sha256 = hashlib.sha256(image_data).hexdigest()
  reject_image(root, image_sha256)
  if selected_entry(root) != C.STOCK_ENTRY:
    raise ValueError("Current boot is not the healthy stock entry")
  if present(root, ONESHOT):
    raise ValueError("Another one-shot boot is already armed")
  original = validate_limine_production(root, provenance.get("production_uki_sha256"))
  production, _line = production_path_line(root)
  verify_production_sections(production, image_data, provenance["production_uki_sha256"])
  text = original.decode()
  if C.BEGIN in text or C.END in text or "/" + C.ENTRY_PREFIX in text or C.ESP_IMAGE in text:
    raise ValueError("An unowned upstream-model entry already exists")
  POLICY.limine_canonical(original)
  require_esp_space(root, len(image_data))

  state.mkdir(parents=True, mode=0o700, exist_ok=True)
  state.chmod(0o700)
  receipt = {
    "schema": SCHEMA,
    "state": "preparing",
    "protocol": C.PROTOCOL,
    "kernel_policy": "production-linux-unchanged",
    "entry_id": C.entry_id(image_sha256),
    "image_sha256": image_sha256,
    "image_blake2": hashlib.blake2b(image_data).hexdigest(),
    "provenance_sha256": provenance_sha256,
    "experiment_id": provenance["experiment_id"],
    "production_uki_sha256": provenance["production_uki_sha256"],
    "modules": {name: {"sha256": value["sha256"], "srcversion": value["srcversion"]} for name, value in provenance["modules"].items()},
    "original_limine_sha256": C.sha256(original),
    "pair_receipt_sha256": pair_receipt_sha256(root),
    "armed_from_boot_id": None,
    "test_boot_id": None,
    "last_armed_cycle": 0,
  }
  try:
    atomic_write(rooted(root, C.BACKUP), original, 0o600)
    save_receipt(root, receipt)
  except Exception as failure:
    try:
      if present(root, C.RECEIPT):
        recover_failed_stage(root, receipt, failure)
      else:
        clean_unpublished_stage(root)
    except Exception as recovery_failure:
      raise RuntimeError(f"Preparing staging failed ({failure}); recovery also failed ({recovery_failure})") from failure
    raise
  try:
    atomic_write(rooted(root, ESP_IMAGE), image_data, 0o600)
    # snapper may have rewritten its region since the first read: judge the fresh bytes against the
    # backup canonically, then append the block to exactly those bytes.
    fresh = read_limine(root)
    if C.BEGIN.encode() in fresh or POLICY.limine_canonical(fresh) != POLICY.limine_canonical(original):
      raise ValueError("Limine changed beyond the snapshot region while staging")
    staged = fresh + entry_block(receipt)
    atomic_write(rooted(root, LIMINE), staged, 0o600)
    receipt["staged_limine_sha256"] = C.sha256(staged)
    verify_staged(root, receipt)
    receipt["state"] = "staged"
    save_receipt(root, receipt)
  except Exception as failure:
    try:
      recover_failed_stage(root, receipt, failure)
    except Exception as recovery_failure:
      raise RuntimeError(f"Staging failed ({failure}); recovery also failed ({recovery_failure})") from failure
    raise
  return receipt


# ---- Arming ------------------------------------------------------------------------

def advertised(root, receipt):
  entries = rooted(root, ENTRIES)
  if not entries.is_file() or receipt["entry_id"] not in SINGLE.read_efi_strings(entries):
    raise ValueError("Limine has not advertised the upstream-model entry; boot stock once after staging")


def common_arm_checks(root, receipt):
  if receipt.get("kernel_policy") != "production-linux-unchanged":
    raise ValueError("Receipt lacks the production-kernel boot policy")
  reject_image(root, receipt["image_sha256"])
  if is_terminal(root, receipt["image_sha256"]):
    raise ValueError("Image hash is terminal after a failed or ambiguous attempt")
  require_maintenance(root)
  verify_staged(root, receipt)
  if present(root, ONESHOT) or present(root, DEFAULT):
    raise ValueError("An EFI one-shot or persistent default is already present")
  advertised(root, receipt)


def set_oneshot(root, receipt, target, runner, sync):
  sync()
  runner(["bootctl", "set-oneshot", target], check=True)
  one_shot = rooted(root, ONESHOT)
  if not one_shot.is_file() or SINGLE.read_efi_string(one_shot) != target:
    raise ValueError("LoaderEntryOneShot verification failed")


def arm(root, runner=subprocess.run, sync=os.sync):
  """First boot of the image: only from the healthy stock boot, and never once an S4 cycle was armed."""
  with locks(root):
    return _arm(root, runner, sync)


def _arm(root, runner, sync):
  receipt = load_receipt(root)
  if receipt.get("state") not in ("staged", "armed", "booted", "disarmed"):
    raise ValueError("Upstream-model transaction cannot be armed from state " + str(receipt.get("state")))
  if receipt.get("last_armed_cycle", 0) > 0 and receipt["state"] != "disarmed":
    raise ValueError("An S4 cycle was armed on this image; its state is not recoverable by re-arming")
  common_arm_checks(root, receipt)
  if selected_entry(root) != C.STOCK_ENTRY:
    raise ValueError("Boot arming requires the healthy stock boot")
  receipt.update(state="arming", arming={"purpose": "boot", "boot_id": current_boot_id(root)},
                 armed_from_boot_id=current_boot_id(root), test_boot_id=None)
  save_receipt(root, receipt)
  set_oneshot(root, receipt, receipt["entry_id"], runner, sync)
  receipt["state"] = "armed"
  save_receipt(root, receipt)
  return receipt


def arm_s4(root, cycle, runner=subprocess.run, sync=os.sync):
  """Before an S4 cycle: only from the test boot, for the next (or the same, after disarm) cycle."""
  if type(cycle) is not int or not 1 <= cycle <= 3:
    raise ValueError("S4 cycle must be 1, 2 or 3")
  with locks(root):
    return _arm_s4(root, cycle, runner, sync)


def _arm_s4(root, cycle, runner, sync):
  receipt = load_receipt(root)
  if receipt.get("state") not in ("booted", "disarmed"):
    raise ValueError("Upstream-model transaction cannot be armed for S4 from state " + str(receipt.get("state")))
  common_arm_checks(root, receipt)
  if selected_entry(root) != receipt["entry_id"]:
    raise ValueError("S4 arming requires the exact upstream-model test boot")
  boot_id = current_boot_id(root)
  if receipt.get("test_boot_id") != boot_id:
    raise ValueError("S4 arming requires the boot that verified the image")
  last = receipt.get("last_armed_cycle", 0)
  allowed = (last, last + 1) if receipt["state"] == "disarmed" else (last + 1,)
  if cycle not in allowed or cycle < 1:
    raise ValueError("S4 cycle out of order: last armed " + str(last))
  receipt.update(state="arming", arming={"purpose": "s4", "cycle": cycle, "boot_id": boot_id})
  save_receipt(root, receipt)
  set_oneshot(root, receipt, receipt["entry_id"], runner, sync)
  receipt.update(state="s4-armed", last_armed_cycle=cycle)
  save_receipt(root, receipt)
  return receipt


def mark_booted(root):
  """Record that the armed one-shot was consumed by this exact test boot (or the S4 return to it).

  An interrupted arm leaves state "arming"; the recorded purpose decides which arm it was.
  """
  receipt = load_receipt(root)
  state = receipt.get("state")
  if state == "arming":
    state = "armed" if (receipt.get("arming") or {}).get("purpose") == "boot" else "s4-armed"
  if state not in ARMED:
    raise ValueError("No armed upstream-model boot to confirm")
  verify_staged(root, receipt, pair=False)
  if present(root, ONESHOT) or present(root, DEFAULT):
    raise ValueError("LoaderEntryOneShot was not consumed")
  if selected_entry(root) != receipt["entry_id"]:
    raise ValueError("Running boot is not the exact upstream-model entry")
  boot_id = current_boot_id(root)
  if state == "armed":
    if boot_id == receipt.get("armed_from_boot_id"):
      raise ValueError("One-shot was not consumed by a new boot")
    receipt["test_boot_id"] = boot_id
  elif boot_id != receipt.get("test_boot_id"):
    raise ValueError("S4 return boot ID differs from the verified test boot")
  receipt["state"] = "booted"
  receipt.pop("arming", None)
  save_receipt(root, receipt)
  return receipt


def adopt_boot(root):
  """Recovery: a consumed one-shot booted the test image on a boot the receipt did not expect.

  Used by the runner's recover step on the test boot itself: the current boot becomes the test boot and
  the receipt moves to "booted" (verify-boot must then pass on it). Evidence and guards are untouched.

  This deliberately skips the boot-id checks that mark_booted makes (armed_from_boot_id / test_boot_id),
  because the boot being adopted is by definition not the one the receipt expected. It stays safe because
  every attempt that owned a guard was already made terminal by the runner's reconcile step before adopt,
  arming refuses terminal images, and verify-boot (selected entry, cmdline, srcversions, health, typed
  confirmation) must be re-run on the adopted boot before any S3 or S4 step will proceed.
  """
  receipt = load_receipt(root)
  if receipt.get("state") not in ARMED + ("arming",):
    raise ValueError("No armed or interrupted upstream-model boot to adopt")
  verify_staged(root, receipt, pair=False)
  if present(root, ONESHOT) or present(root, DEFAULT):
    raise ValueError("An EFI one-shot or default is still present; disarm it first")
  if selected_entry(root) != receipt["entry_id"]:
    raise ValueError("Running boot is not the exact upstream-model entry")
  receipt["test_boot_id"] = current_boot_id(root)
  receipt["state"] = "booted"
  receipt.pop("arming", None)
  save_receipt(root, receipt)
  return receipt


def disarm(root, runner=subprocess.run):
  receipt = load_receipt(root)
  if receipt.get("state") == "disarmed" and not present(root, ONESHOT):
    return receipt
  if receipt.get("state") not in ARMED + ("arming",):
    raise ValueError("No upstream-model one-shot is armed")
  verify_staged(root, receipt, pair=False)
  purpose = (receipt.get("arming") or {}).get("purpose")
  if purpose == "s4":
    if selected_entry(root) != receipt["entry_id"] or current_boot_id(root) != receipt.get("test_boot_id"):
      raise ValueError("An S4 one-shot may only be disarmed from its own test boot")
  elif selected_entry(root) != C.STOCK_ENTRY:
    raise ValueError("A boot one-shot may only be disarmed from the stock boot")
  one_shot = rooted(root, ONESHOT)
  if one_shot.exists():
    if SINGLE.read_efi_string(one_shot) != receipt["entry_id"]:
      raise ValueError("Refusing to clear an unknown one-shot entry")
    runner(["bootctl", "set-oneshot", ""], check=True)
    if one_shot.exists():
      raise ValueError("One-shot remained after disarming")
  elif receipt["state"] != "arming":
    raise ValueError("One-shot is already consumed; confirm the boot instead of disarming")
  receipt["state"] = "disarmed"
  save_receipt(root, receipt)
  return receipt


# ---- Rollback and clear ------------------------------------------------------------

def rollback(root):
  with locks(root):
    return _rollback(root)


def _rollback(root):
  receipt = load_receipt(root)
  if present(root, ONESHOT):
    raise ValueError("Disarm LoaderEntryOneShot before rollback")
  if selected_entry(root) != C.STOCK_ENTRY:
    raise ValueError("Rollback requires the stock boot")
  state = receipt.get("state")
  if state == "rolled-back":
    verify_recovered(root, receipt)
    return receipt
  if state == "stage-failed-recovered":
    verify_recovered(root, receipt)
    receipt["state"] = "rolled-back"
    save_receipt(root, receipt)
    return receipt
  if state in ("staged", "armed", "booted", "s4-armed", "disarmed", "arming"):
    receipt["state"] = "rolling-back"
    save_receipt(root, receipt)
  elif state != "rolling-back":
    raise ValueError("Upstream-model transaction cannot be rolled back from state " + str(state))
  backup = rooted(root, C.BACKUP)
  if not backup.is_file():
    raise ValueError("Upstream-model Limine backup is missing")
  remove_limine_block(root, receipt)
  remove_image(root, receipt)
  verify_recovered(root, receipt)
  receipt["state"] = "rolled-back"
  save_receipt(root, receipt)
  return receipt


def clear_rolled_back(root):
  if present(root, ONESHOT):
    raise ValueError("Disarm LoaderEntryOneShot before clearing upstream-model state")
  state = rooted(root, C.STATE)
  if not state.exists():
    return {"state": "cleared"}
  validate_state(state, STATE_FILES)
  receipt_path, backup = rooted(root, C.RECEIPT), rooted(root, C.BACKUP)
  if not receipt_path.exists():
    if backup.exists():
      raise ValueError("Backup remains without a receipt")
    return {"state": "cleared"}
  receipt = load_receipt(root)
  if receipt.get("state") != "rolled-back":
    raise ValueError("Upstream-model transaction must be rolled back before clearing")
  if selected_entry(root) != C.STOCK_ENTRY:
    raise ValueError("Clearing requires the stock boot")
  verify_recovered(root, receipt)
  if backup.exists():
    backup.unlink()
    fsync_directory(state)
  receipt_path.unlink()
  fsync_directory(state)
  # Guards, attempts and terminal markers are evidence and are never removed here.
  return {**receipt, "state": "cleared"}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("action", choices=("stage", "verify", "arm", "arm-s4", "mark-booted", "disarm", "rollback", "clear", "status"))
  parser.add_argument("--build", type=Path, help="root-owned build directory (stage only)")
  parser.add_argument("--cycle", type=int, help="S4 cycle number (arm-s4 only)")
  args = parser.parse_args()
  if os.geteuid() != 0:
    raise SystemExit("Root required")
  root = Path("/")
  try:
    if args.action == "stage":
      if args.build is None:
        parser.error("stage requires --build")
      result = stage(root, args.build.resolve())
    elif args.action == "arm":
      result = arm(root)
    elif args.action == "arm-s4":
      if args.cycle is None:
        parser.error("arm-s4 requires --cycle")
      result = arm_s4(root, args.cycle)
    elif args.action == "mark-booted":
      result = mark_booted(root)
    elif args.action == "disarm":
      result = disarm(root)
    elif args.action == "rollback":
      result = rollback(root)
    elif args.action == "clear":
      result = clear_rolled_back(root)
    elif args.action == "status":
      result = load_receipt(root)
    else:
      result = load_receipt(root)
      verify_staged(root, result)
  except (OSError, RuntimeError, ValueError) as error:
    raise SystemExit("Upstream-model stager refused: " + str(error)) from error
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
