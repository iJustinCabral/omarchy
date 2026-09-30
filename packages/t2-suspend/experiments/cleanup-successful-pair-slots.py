#!/usr/bin/python3
"""Retire the two reusable stage slots of one exact, completed, successful pair S4 vector.

Generation-aware successor of the pinned 7.2.6 cleanup-successful-v16-slots.py
(which stays unchanged as historical evidence). Nothing is pinned here: the
operator names a vector, and everything is derived from that vector's own
durable evidence under s4-vectors/<vector>/ and from the currently staged pair.

Default is read-only. --execute archives the vector evidence and the raw EFI
variables (root 0700), then deletes only the V3 source stage and V2 restore
stage variables. It is idempotent and crash-safe: every archive file is written
atomically, deletion is journalled (delete-intent before, absent record after),
and a rerun completes exactly the journalled state or refuses. The consumed
guard, attempt, Entered/Armed hook witnesses, acceptance and receipt are never
touched. No PM, module, boot-override or other EFI operation exists here.
efivarfs deletion relies on serialized operators; the kernel offers no atomic
compare-and-delete.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


def module(name, relative):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / relative)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


V16 = module("pair_cleanup_v16_helpers", "cleanup-successful-v16-slots.py")
HOST, PAIR, EFI = V16.HOST, V16.PAIR, V16.EFI
SOURCE, RESTORE = V16.SOURCE, V16.RESTORE
SLOTS = (SOURCE, RESTORE)
GUID = HOST.CT.GUID
ARCHIVE_ROOT = Path("var/lib/omarchy-t2-hibernation-pair-slot-cleanup")
VECTORS = PAIR.STATE / "s4-vectors"
ACCEPTANCE = Path("var/lib/omarchy-t2-postwrite-marker/recovery-acceptance-v3.json")
SCHEMA = "successful-pair-slot-clear-v1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
ATTEMPT_FILES = ("attempt.json", "cold-pci-restore-context.json", "cold-pci-restore-return-raw.json",
                 "cold-pci-restore-return.json", "cold-pci-restore-observation.json", "cold-pci-restore-health.json",
                 "cold-pci-restored-source-witness.json", "postwrite-efi-identity.json", "restore-efi-identity.json")
exact = V16.exact


def sha(raw):
  return hashlib.sha256(raw).hexdigest()


def jload(raw):
  value = json.loads(raw)
  if not isinstance(value, dict): raise ValueError("Evidence is not an object")
  return value


def hooks(vector):
  return tuple("OmarchyT2RestoreHook" + suffix + vector[:24] + "-" + GUID for suffix in ("Entered", "Armed"))


def canonical_stages(vector):
  prefix = vector[:24]
  stages = {SOURCE: b"\x07\0\0\0MBPW" + bytes.fromhex(prefix) + b"\x04",
            RESTORE: b"\x07\0\0\0MBRS" + bytes.fromhex(prefix) + b"\x07"}
  for index, name in enumerate(hooks(vector), 1):
    stages[name] = b"\x07\0\0\0MBRH" + prefix.encode() + bytes((index,))
  return stages


def pair_vector(receipt):
  parts = (receipt["images"]["source"]["sha256"], receipt["images"]["restore"]["sha256"], receipt["runtime_stack_sha256"])
  for part in parts:
    if not isinstance(part, str) or HEX64.match(part) is None: raise ValueError("Malformed receipt identity")
  return hashlib.sha256(":".join(parts).encode()).hexdigest()


def collect(root, vector):
  """Check the vector's durable evidence against the staged pair."""
  if HEX64.match(vector) is None: raise ValueError("Vector must be 64 lowercase hex digits")
  live = VECTORS / vector
  receipt_raw = V16.read(root, PAIR.STATE / "receipt.json", True)
  receipt = jload(receipt_raw)
  exact(pair_vector(receipt), vector)  # exactly the currently staged pair
  guard = V16.read(root, live / "s4-attempted", True)
  boot = guard.decode().strip()
  if UUID.match(boot) is None or guard != (boot + "\n").encode(): raise ValueError("Malformed pair guard")
  exact([item.name for item in V16.path(root, live / "attempts").iterdir()], [boot])
  files = {"receipt.json": receipt_raw, "vector-s4-attempted": guard}
  for name in ATTEMPT_FILES:
    files["attempt-" + name] = V16.read(root, live / "attempts" / boot / name, True)
  acceptance_raw = V16.read(root, ACCEPTANCE, True)
  files["recovery-acceptance-v3.json"] = acceptance_raw
  images = receipt["images"]
  attempt = jload(files["attempt-attempt.json"])
  for key, value in (("boot_id", boot), ("transition_vector", vector), ("state", "returned-and-cleaned"),
                     ("real_s4_attempted", True), ("hibernate_attempted", True),
                     ("source_uki_sha256", images["source"]["sha256"]), ("restore_uki_sha256", images["restore"]["sha256"]),
                     ("runtime_stack_sha256", receipt["runtime_stack_sha256"]),
                     ("source_entry_id", images["source"]["entry_id"]), ("restore_entry_id", images["restore"]["entry_id"]),
                     ("recovery_method", "operator-attended-cold-power"),
                     ("postwrite-efi_stage", 4), ("restore-efi_stage", 7), ("restore-hook-efi_stage", 2)):
    exact(attempt.get(key), value)
  if attempt.get("cleanup_errors") or attempt.get("error"): raise ValueError("Attempt recorded errors")
  if not isinstance(attempt.get("kernel_release"), str) or not attempt["kernel_release"]: raise ValueError("No recorded kernel")
  stages = canonical_stages(vector)
  raw = jload(files["attempt-cold-pci-restore-return-raw.json"])
  exact(raw["boot_id"], boot)
  exact(raw["read_errors"], [])
  exact(raw["abort_witnesses"], [])
  exact(raw["efi_overrides"], {"LoaderEntryDefault": None, "LoaderEntryOneShot": None})
  exact(raw["markers"], {name: value.hex() for name, value in stages.items()})  # the values this run recorded
  witness = jload(files["attempt-cold-pci-restored-source-witness.json"])
  exact(witness["continuity"], "conditional-on-trusted-original-source-runner-process")
  proof = witness["proof"]
  for key, value in (("classification", "source-return-evidence-valid"), ("post_cleanup_health_valid", True), ("boot_id", boot),
                     ("transition_vector", vector), ("usable_hibernation_qualified", False)):
    exact(proof.get(key), value)
  if not isinstance(proof.get("return_nonce"), str) or not proof["return_nonce"]: raise ValueError("No return nonce")
  exact(witness["observation"]["return_capture"]["markers"], raw["markers"])
  for key, value in (("boot_id", boot), ("transition_vector", vector), ("source_uki_sha256", images["source"]["sha256"]),
                     ("restore_uki_sha256", images["restore"]["sha256"]), ("production_uki_sha256", receipt["production_uki_sha256"]),
                     ("runtime_stack_sha256", receipt["runtime_stack_sha256"])):
    exact(witness["expected"].get(key), value)
  acceptance = jload(acceptance_raw)
  exact({key: value for key, value in acceptance.items() if key not in ("module_sha256", "restore_module_sha256")},
        {"kind": "postwrite-restore-efi-attended-s4-v3", "boot_id": boot, "transition_vector": vector,
         "production_uki_sha256": receipt["production_uki_sha256"], "method": "operator-attended-cold-power", "accepted": True,
         "source_efi_variable": SOURCE, "restore_efi_variable": RESTORE})
  record = {"schema": SCHEMA, "vector": vector, "boot_id": boot, "kernel_release": attempt["kernel_release"],
            "slots": list(SLOTS), "evidence_sha256": {name: sha(value) for name, value in sorted(files.items())},
            "raw_markers_sha256": {name: sha(value) for name, value in sorted(stages.items())}, "product_qualified": False}
  return files, receipt, record, stages, boot, attempt


def platform(root, receipt, boot, attempt):
  """Same boot: resumed source with the restore entry selected. Later boot: ordinary source entry."""
  exact(V16.read(root, Path("proc/sys/kernel/osrelease")).decode().strip(), attempt["kernel_release"])
  current = V16.read(root, Path("proc/sys/kernel/random/boot_id")).decode().strip()
  entry = receipt["images"]["restore" if current == boot else "source"]["entry_id"]
  exact(V16.read(root, EFI / ("LoaderEntrySelected-" + HOST.HOST.LOADER_GUID)), b"\x06\0\0\0" + (entry + "\0").encode("utf-16-le"))
  for name in ("LoaderEntryOneShot", "LoaderEntryDefault"):
    target = V16.path(root, EFI / (name + "-" + HOST.HOST.LOADER_GUID))
    if target.exists() or target.is_symlink(): raise ValueError("EFI override remains")
  loaded = {line.split()[0] for line in V16.read(root, Path("proc/modules")).decode().splitlines() if line.split()}
  loaded |= {item.name for item in V16.path(root, Path("sys/module")).iterdir()}
  if any(name.startswith("mba_hibernate_") or "abort" in name.lower() for name in loaded): raise ValueError("Marker/cold/abort writer loaded")
  # /proc/self is a native symlink, so resolve it with the v16 confined runtime resolver
  mounts = [line.split() for line in HOST.HOST._raw(V16.runtime_path(root, Path("proc/self/mounts"))).decode().splitlines() if len(line.split()) >= 4 and line.split()[1] == "/"]
  if len(mounts) != 1 or mounts[0][0:3] != ["/dev/mapper/root", "/", "btrfs"] or "subvol=/@" not in mounts[0][3].split(","):
    raise ValueError("Primary encrypted root changed")
  for role, relative in {**PAIR.IMAGES, "production": Path("boot/EFI/Linux/omarchy_linux-t2.efi")}.items():
    exact(V16.digest_file(root, relative), receipt["production_uki_sha256"] if role == "production" else receipt["images"][role]["sha256"])
  exact(V16.digest_file(root, PAIR.SINGLE.LIMINE), receipt["staged_limine_sha256"])
  exact(V16.digest_file(root, PAIR.BACKUP), receipt["original_limine_sha256"])
  old_digest, old_blake = PAIR.digest, PAIR.SINGLE.blake2
  try:
    PAIR.digest = lambda value: V16.digest_file(root, Path(value).relative_to(root))
    PAIR.SINGLE.blake2 = lambda value: V16.digest_file(root, Path(value).relative_to(root), "blake2b")
    PAIR.verify_staged(root, receipt)
  finally:
    PAIR.digest, PAIR.SINGLE.blake2 = old_digest, old_blake


def fsync_dir(directory):
  fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
  try: os.fsync(fd)
  finally: os.close(fd)


def owner(root):
  return 0 if Path(root) == Path("/") else os.geteuid()


def archive_paths(root, vector, create):
  base = V16.path(root, ARCHIVE_ROOT)
  if create and not base.exists():
    base.mkdir(mode=0o700)
    fsync_dir(base.parent)
  if base.exists() and (base.stat().st_uid != owner(root) or stat.S_IMODE(base.stat().st_mode) != 0o700):
    raise ValueError("Unsafe cleanup archive root")
  directory = base / vector
  if create and not directory.exists():
    directory.mkdir(mode=0o700)
    fsync_dir(base)
  if directory.exists() and (directory.is_symlink() or directory.stat().st_uid != owner(root) or stat.S_IMODE(directory.stat().st_mode) != 0o700):
    raise ValueError("Unsafe vector cleanup archive")
  return base, directory


def put(root, directory, name, raw):
  """Atomic durable create, or byte-exact verification when it already exists."""
  target = directory / name
  if target.exists() or target.is_symlink():
    exact(V16.read(root, target.relative_to(root), True), raw)
    return
  temporary = directory / (".tmp-" + name)
  if temporary.exists() or temporary.is_symlink(): temporary.unlink()  # stale partial from a crashed run
  V16.durable_new(temporary, raw)
  os.rename(temporary, target)
  fsync_dir(directory)


def put_json(root, directory, name, value):
  put(root, directory, name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def verify_complete(root, vector, directory):
  relative = directory.relative_to(root)
  record = jload(V16.read(root, relative / "complete.json", True))
  intent = jload(V16.read(root, relative / "intent.json", True))
  exact(intent.get("vector"), vector)
  exact(record, {**intent, "slots_cleared": True, "guards_and_witnesses_preserved": True})
  for name, digest in intent["evidence_sha256"].items():
    exact(sha(V16.read(root, relative / name, True)), digest)
  for name in SLOTS:
    exact(sha(V16.read(root, relative / ("raw-" + name), True)), intent["raw_markers_sha256"][name])
    target = V16.path(root, EFI / name)
    if target.exists() or target.is_symlink(): raise ValueError("Cleared slot reappeared")
  return record


def inspect(root, vector):
  """Read-only. Returns (state, context) with state 'complete' or 'ready'."""
  root = Path(root)
  if HEX64.match(vector) is None: raise ValueError("Vector must be 64 lowercase hex digits")
  _, directory = archive_paths(root, vector, False)
  if (directory / "complete.json").exists():
    return "complete", verify_complete(root, vector, directory)
  files, receipt, record, stages, boot, attempt = collect(root, vector)
  platform(root, receipt, boot, attempt)
  for name in hooks(vector):
    exact(V16.read(root, EFI / name), stages[name])
  started = (directory / "intent.json").exists()
  for name in SLOTS:
    target = V16.path(root, EFI / name)
    if target.exists() or target.is_symlink():
      if (directory / (name + ".absent.json")).exists(): raise ValueError("Confirmed slot reappeared")
      exact(V16.read(root, EFI / name), stages[name])
    elif not started or not (directory / (name + ".delete-intent.json")).exists():
      raise ValueError("Slot missing without a durable delete intent; no retry")
  if started: exact(jload(V16.read(root, directory.relative_to(root) / "intent.json", True)), record)
  return "ready", (record, files, stages)


def validate(root, vector):
  state, context = inspect(root, vector)
  return context if state == "complete" else context[0]


def execute(root, vector, *, remover=None):
  root = Path(root)
  if root == Path("/") and remover is not None: raise ValueError("No injected live deletion backend")
  state, context = inspect(root, vector)
  if state == "complete": return context
  record, files, stages = context
  base, directory = archive_paths(root, vector, True)
  fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state, context = inspect(root, vector)  # again, now serialized
    if state == "complete": return context
    for name, raw in files.items(): put(root, directory, name, raw)
    for name in (*SLOTS, *hooks(vector)): put(root, directory, "raw-" + name, stages[name])
    put_json(root, directory, "intent.json", record)
    for name in SLOTS:
      digest = {"slot": name, "sha256": sha(stages[name])}
      target = V16.path(root, EFI / name)
      if target.exists() or target.is_symlink():
        inspect(root, vector)
        put_json(root, directory, name + ".delete-intent.json", digest)
        if remover is None: V16.owned_delete(root, name, stages[name])
        else: remover(target, stages[name])
        if V16.path(root, EFI / name).exists(): raise ValueError("Slot remains after deletion")
      else:
        exact(jload(V16.read(root, directory.relative_to(root) / (name + ".delete-intent.json"), True)), digest)
      put_json(root, directory, name + ".absent.json", {**digest, "absent": True})
    completion = {**record, "slots_cleared": True, "guards_and_witnesses_preserved": True}
    for name in hooks(vector): exact(V16.read(root, EFI / name), stages[name])
    put_json(root, directory, "complete.json", completion)
    return completion
  finally: os.close(fd)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--vector", required=True, help="64-hex pair S4 vector whose completed successful run is being cleaned")
  parser.add_argument("--execute", action="store_true", help="archive, then delete only the V3 source and V2 restore stage variables")
  args = parser.parse_args()
  if os.geteuid() != 0: raise SystemExit("Root required for private evidence")
  try:
    result = execute(Path("/"), args.vector) if args.execute else validate(Path("/"), args.vector)
  except (OSError, ValueError, KeyError, TypeError) as error: raise SystemExit("Successful-pair cleanup refused: " + str(error)) from error
  print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__": main()
