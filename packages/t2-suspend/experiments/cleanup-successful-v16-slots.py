#!/usr/bin/python3
"""Retire two reusable slots of the exact successful v16 original-source return.

Default is read-only. No boot/pin override, PM operation, module operation or
vector replay exists. The trusted historical original-process proof is not new
product qualification. Execute is one-use: incomplete cleanup requires review,
not retry. efivarfs deletion relies on serialized operators and absent writers;
there is no kernel atomic compare-and-delete primitive.
"""
import argparse
import array
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


def module(name, relative):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / relative)
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


HOST = module("successful_v16_host", "../hibernate/host_backend.py")
PAIR = module("successful_v16_pair", "stage-hibernation-uki-pair.py")
BOOT = "ed1953ad-859f-4c85-8082-167bac912c63"
VECTOR = "33a2e46e7598c0737daf3eb294ea50088bc60bf526d8cdd163561cd10e447365"
NONCE = "a905f7a0-0565-48b0-9bd7-482a48ddf891"
KERNEL = "7.2.6-arch2-Watanare-T2-2-t2"
ARCHIVE = Path("var/lib/omarchy-t2-ordinary-boot-evidence/v16-fullrestore-33a2e46e")
LIVE = Path("var/lib/omarchy-t2-hibernation-pair/s4-vectors") / VECTOR
ATTEMPT = Path("attempts") / BOOT
CLEANUP = ARCHIVE / "successful-v16-slot-cleanup"
EFI = HOST.HOST.EFI
SOURCE = HOST.CT.SOURCE_VARIABLE
RESTORE = HOST.CT.RESTORE_VARIABLE
HOOKS = tuple("OmarchyT2RestoreHook" + suffix + VECTOR[:24] + "-" + HOST.CT.GUID for suffix in ("Entered", "Armed"))
IMAGE_PINS = {"source": "c5e6f0c9d38ff0d4dcba43e69e32bb1571c35a84ba867c983ec2cab130069ac7",
              "restore": "52c20d2c63a8997b93457ba049b1f8c15ae3d82035f3a46397f12fd91ec15531",
              "production": "18491469d046bd5805a10c7a80e47c1e9ae2af1879a3ce78b1e9c14826c789bc"}
RUNTIME = "bd51428b459e25d429507261c52bb52e717ed9c93416f19e65a0e8675e7191db"
# Raw /proc/cmdline framing, pinned by the original-process witness; this is
# neither the stripped preflight hash nor the UKI .cmdline section hash.
CMDLINE = "6e3547f99532e335104dea2d5fc148a6ee61e43ebffa77fdeeac3e8e6a7b0b75"
PINS = {"receipt.json": "a67740d063f88d68c8aa519ffb93e1f20fd59d7faf670f27980bb0ece2ef8973",
        "recovery-acceptance-v3.json": "04b0934b85d733b9ef101b93f03e3440038b55d7f0cb16f6f341fa99f3006911",
        "vector/s4-attempted": "7b94fff80d66ad2ce25753dc0cb832e5d5b8ef1475e22c0b54d94477dad6c41f"}
for filename, digest in {
  "attempt.json": "a1016e25051976ef2bfe80fa7ca733be01aadadbaa50787d826251d648358553",
  "cold-pci-restore-context.json": "68a9d77d98234daf8aa2b9f7c3401a8a199f1d39801bb0f8995a587a2d6cca29",
  "cold-pci-restore-health.json": "7df9730ad860cbd98d662145df985ca767206fc6f0ddaa9aaaf16121b4dd7077",
  "cold-pci-restore-observation.json": "30d77cc3f122b12e0319f80cac358f325e4ee627ccfbf8cfa2ca6b20f6d98dc5",
  "cold-pci-restore-return-raw.json": "44e912aa1b7e81c7760d5676b7da426c53e391ad8c1e962fb9da1b54e96996c4",
  "cold-pci-restore-return.json": "aa2ec6079148a0affb94293f1cf80adc190e25ce112deacb1a808378a39c5552",
  "cold-pci-restored-source-witness.json": "5caa7f7efd752b8294c280802a2978ebbab8f993d4f0072664f55aa315be2e53",
  "postwrite-efi-identity.json": "b0c3a370be405216bd6f90bf0fd521246021d474c48491ec45430b4e02ab34be",
  "restore-efi-identity.json": "fa5507542c1f6ee20ed993e524d7f1e2313d295f33270889eb30bbffe7a6cf7c"
}.items():
  PINS[str(Path("vector") / ATTEMPT / filename)] = digest


def path(root, relative):
  root = Path(root)
  if not root.is_absolute() or any(item.is_symlink() for item in (root, *root.parents)):
    raise ValueError("Explicit nonsymlink root required")
  relative = Path(relative)
  if relative.is_absolute() or ".." in relative.parts: raise ValueError("Unsafe relative evidence path")
  result = root
  for component in relative.parts:
    result /= component
    if result.is_symlink(): raise ValueError("Symlinked evidence path")
  return result


def read(root, relative, private=False):
  target = path(root, relative)
  info = target.stat()
  owner = 0 if Path(root) == Path("/") else os.geteuid()
  if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024:
    raise ValueError("Unsafe bounded evidence")
  if private and stat.S_IMODE(info.st_mode) != 0o600: raise ValueError("Evidence is not private")
  return HOST.HOST._raw(target)


def digest_file(root, relative, algorithm="sha256"):
  target = path(root, relative)
  if not stat.S_ISREG(target.stat().st_mode): raise ValueError("Not a regular boot artifact")
  digest = hashlib.new(algorithm)
  with target.open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""): digest.update(chunk)
  return digest.hexdigest()


def exact(actual, expected):
  HOST.CT.exact(actual, expected, "Pinned successful-v16 evidence")


def runtime_path(root, relative):
  """Follow native sysfs class/bus links, confined to the supplied host root."""
  relative = Path(relative)
  if relative.is_absolute() or ".." in relative.parts: raise ValueError("Unsafe runtime path")
  result = (Path(root) / relative).resolve(strict=True)
  result.relative_to(Path(root).resolve())
  return result


def record():
  return {"schema": "successful-v16-reusable-slot-clear-v1", "boot_id": BOOT, "vector": VECTOR,
          "historical_evidence_sha256": PINS, "slots": [SOURCE, RESTORE], "product_qualified": False}


def current_platform(root, attempt, receipt, query):
  exact(read(root, Path("proc/sys/kernel/random/boot_id")).decode().strip(), BOOT)
  exact(hashlib.sha256(read(root, Path("proc/cmdline"))).hexdigest(), CMDLINE)
  # Restored source execution has the restore-selected loader variable. This
  # exception is tied only to this pinned original-process successful witness.
  selected = b"\x06\0\0\0" + (receipt["images"]["restore"]["entry_id"] + "\0").encode("utf-16-le")
  exact(read(root, EFI / ("LoaderEntrySelected-" + HOST.HOST.LOADER_GUID)), selected)
  for name in ("LoaderEntryOneShot", "LoaderEntryDefault"):
    if path(root, EFI / (name + "-" + HOST.HOST.LOADER_GUID)).exists(): raise ValueError("EFI override remains")
  HOST.verify_readiness(root, {"audited_details": {"kernel_release": KERNEL, "restore_protocol": {"resume":
                         {"device": "/dev/mapper/root", "devnum": "253:0", "offset": 1923214}}}}, command_runner=query)
  loaded = {line.split()[0] for line in read(root, Path("proc/modules")).decode().splitlines() if line.split()}
  loaded |= {entry.name for entry in path(root, Path("sys/module")).iterdir()}
  if any(name.startswith("mba_hibernate_") or "abort" in name.lower() for name in loaded): raise ValueError("Historical marker/cold/abort writer loaded")
  for name, identity in attempt["modules"].items():
    exact(read(root, Path("sys/module") / name.replace("-", "_") / "srcversion").decode().strip(), identity)
  mounts = [line.split() for line in HOST.HOST._raw(runtime_path(root, Path("proc/self/mounts"))).decode().splitlines() if len(line.split()) >= 4 and line.split()[1] == "/"]
  if len(mounts) != 1 or mounts[0][0:3] != ["/dev/mapper/root", "/", "btrfs"] or "subvol=/@" not in mounts[0][3].split(","):
    raise ValueError("Primary encrypted root changed")
  inputs = read(root, Path("proc/bus/input/devices")).decode()
  if inputs.count('N: Name="Apple Inc. Apple Internal Keyboard / Trackpad"') < 2 or inputs.count("Phys=usb-t2bce_vhci-") < 2:
    raise ValueError("Internal input enumeration missing")
  if "Apple T2 Audio" not in read(root, Path("proc/asound/cards")).decode(): raise ValueError("T2 audio missing")
  if len(list(runtime_path(root, Path("sys/bus/pci/devices/0000:73:00.0/net")).iterdir())) != 1 or not runtime_path(root, Path("sys/class/bluetooth/hci0")).is_dir():
    raise ValueError("Radio enumeration missing")
  if not any(HOST.HOST._raw(runtime_path(root, item.relative_to(root) / "type")).strip() == b"Mains" and HOST.HOST._raw(runtime_path(root, item.relative_to(root) / "online")).strip() == b"1" for item in runtime_path(root, Path("sys/class/power_supply")).iterdir()):
    raise ValueError("Live AC missing")
  for role, relative in {**PAIR.IMAGES, "production": Path("boot/EFI/Linux/omarchy_linux-t2.efi")}.items():
    exact(digest_file(root, relative), IMAGE_PINS[role])
  exact(digest_file(root, PAIR.SINGLE.LIMINE), receipt["staged_limine_sha256"])
  exact(digest_file(root, PAIR.BACKUP), receipt["original_limine_sha256"])
  # Reuse structural stock-fallback/menu checks, substituting only streaming
  # digest functions, never the ordinary-source selected-entry verifier.
  old_digest, old_blake = PAIR.digest, PAIR.SINGLE.blake2
  try:
    PAIR.digest = lambda value: digest_file(root, Path(value).relative_to(root))
    PAIR.SINGLE.blake2 = lambda value: digest_file(root, Path(value).relative_to(root), "blake2b")
    PAIR.verify_staged(root, receipt)
  finally:
    PAIR.digest, PAIR.SINGLE.blake2 = old_digest, old_blake


def validate(root=Path("/"), *, query=None):
  root = Path(root)
  if root == Path("/") and query is not None: raise ValueError("No injected live platform backend")
  archive = path(root, ARCHIVE)
  owner = 0 if root == Path("/") else os.geteuid()
  if archive.stat().st_uid != owner or stat.S_IMODE(archive.stat().st_mode) != 0o700: raise ValueError("Unsafe success archive")
  values = {}
  for name, pin in PINS.items():
    raw = read(root, ARCHIVE / name, True)
    exact(hashlib.sha256(raw).hexdigest(), pin)
    values[name] = raw
    if name.startswith("vector/"): exact(read(root, LIVE / name.removeprefix("vector/"), True), raw)
  exact(read(root, PAIR.STATE / "receipt.json", True), values["receipt.json"])
  exact(read(root, Path("var/lib/omarchy-t2-postwrite-marker/recovery-acceptance-v3.json"), True), values["recovery-acceptance-v3.json"])
  exact(values["vector/s4-attempted"], (BOOT + "\n").encode())
  prefix = str(Path("vector") / ATTEMPT) + "/"
  attempt = json.loads(values[prefix + "attempt.json"])
  for key, expected in (("boot_id", BOOT), ("transition_vector", VECTOR), ("state", "returned-and-cleaned"), ("real_s4_attempted", True)):
    exact(attempt[key], expected)
  witness = json.loads(values[prefix + "cold-pci-restored-source-witness.json"])
  exact(witness["continuity"], "conditional-on-trusted-original-source-runner-process")
  for key, expected in (("classification", "source-return-evidence-valid"), ("post_cleanup_health_valid", True),
                        ("boot_id", BOOT), ("transition_vector", VECTOR), ("return_nonce", NONCE), ("usable_hibernation_qualified", False)):
    exact(witness["proof"][key], expected)
  raw = json.loads(values[prefix + "cold-pci-restore-return-raw.json"])
  exact(raw["boot_id"], BOOT)
  exact(raw["read_errors"], [])
  exact(raw["abort_witnesses"], [])
  exact(raw["efi_overrides"], {"LoaderEntryDefault": None, "LoaderEntryOneShot": None})
  stages = {SOURCE: b"\x07\0\0\0MBPW" + bytes.fromhex(VECTOR[:24]) + b"\x04",
            RESTORE: b"\x07\0\0\0MBRS" + bytes.fromhex(VECTOR[:24]) + b"\x07",
            **{name: b"\x07\0\0\0MBRH" + VECTOR[:24].encode() + bytes((i,)) for i, name in enumerate(HOOKS, 1)}}
  exact(raw["markers"], {name: value.hex() for name, value in stages.items()})
  receipt = json.loads(values["receipt.json"])
  for role in ("source", "restore"): exact(receipt["images"][role]["sha256"], IMAGE_PINS[role])
  exact(receipt["production_uki_sha256"], IMAGE_PINS["production"])
  exact(receipt["runtime_stack_sha256"], RUNTIME)
  current_platform(root, attempt, receipt, query)
  for name in HOOKS: exact(read(root, EFI / name), stages[name])
  directory = path(root, CLEANUP)
  intent = directory / "intent.json"
  if directory.exists():
    if not intent.exists(): raise ValueError("Incomplete archive preparation; no retry")
    exact(json.loads(read(root, CLEANUP / "intent.json", True)), record())
    for name, expected in stages.items(): exact(read(root, CLEANUP / name, True), expected)
  for name in (SOURCE, RESTORE):
    slot = path(root, EFI / name)
    confirmation = directory / (name + ".absent.json")
    if slot.exists():
      if confirmation.exists(): raise ValueError("Confirmed slot reappeared")
      exact(read(root, EFI / name), stages[name])
    elif not intent.exists() or not confirmation.exists(): raise ValueError("Missing slot without durable confirmed absence; no retry")
    else:
      exact(json.loads(read(root, CLEANUP / (name + ".delete-intent.json"), True)), {"slot": name, "sha256": hashlib.sha256(stages[name]).hexdigest()})
      exact(json.loads(read(root, CLEANUP / confirmation.name, True)), {"slot": name, "sha256": hashlib.sha256(stages[name]).hexdigest(), "absent": True})
  completed = directory / "complete.json"
  if completed.exists():
    exact(json.loads(read(root, CLEANUP / "complete.json", True)), {**record(), "slots_cleared": True, "guards_and_witnesses_preserved": True})
    if any(path(root, EFI / name).exists() for name in (SOURCE, RESTORE)): raise ValueError("Incomplete completed cleanup")
  return record(), stages


def durable_new(target, raw):
  fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  try:
    if os.write(fd, raw) != len(raw): raise OSError("Short durable archive write")
    os.fsync(fd)
  finally: os.close(fd)
  parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
  try: os.fsync(parent)
  finally: os.close(parent)


def new_json(target, value):
  durable_new(target, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def owned_delete(root, name, expected):
  target = path(root, EFI / name)
  fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  original_flags = None
  deleted = False
  try:
    info = os.fstat(fd)
    exact(os.read(fd, 1024), expected)
    if (target.stat().st_dev, target.stat().st_ino) != (info.st_dev, info.st_ino): raise ValueError("Slot inode changed")
    if root == Path("/"): original_flags = HOST._clear_immutable(fd)
    os.lseek(fd, 0, os.SEEK_SET)
    exact(os.read(fd, 1024), expected)
    if (target.stat().st_dev, target.stat().st_ino) != (info.st_dev, info.st_ino): raise ValueError("Slot path changed before removal")
    target.unlink()
    deleted = True
    if root == Path("/"): os.sync()
  finally:
    try:
      if not deleted and original_flags is not None and original_flags & HOST.FS_IMMUTABLE_FL:
        fcntl.ioctl(fd, HOST.FS_IOC_SETFLAGS, array.array("L", [original_flags]), True)
    finally: os.close(fd)


def execute(root=Path("/"), *, query=None, remover=None):
  root = Path(root)
  if root == Path("/") and remover is not None: raise ValueError("No injected live deletion backend")
  fd = os.open(path(root, ARCHIVE), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result, stages = validate(root, query=query)
    directory = path(root, CLEANUP)
    if directory.exists(): raise ValueError("Cleanup already started; no repeated or uncertain deletion")
    directory.mkdir(mode=0o700)
    os.fsync(fd)
    for name, raw in stages.items(): durable_new(directory / name, raw)
    for name, raw in stages.items(): exact(read(root, CLEANUP / name, True), raw)
    new_json(directory / "intent.json", result)
    for name in (SOURCE, RESTORE):
      validate(root, query=query)
      new_json(directory / (name + ".delete-intent.json"), {"slot": name, "sha256": hashlib.sha256(stages[name]).hexdigest()})
      if remover is None: owned_delete(root, name, stages[name])
      else: remover(path(root, EFI / name), stages[name])
      if path(root, EFI / name).exists(): raise ValueError("Slot remains after deletion")
      new_json(directory / (name + ".absent.json"), {"slot": name, "sha256": hashlib.sha256(stages[name]).hexdigest(), "absent": True})
    validate(root, query=query)
    completion = {**result, "slots_cleared": True, "guards_and_witnesses_preserved": True}
    new_json(directory / "complete.json", completion)
    return completion
  finally: os.close(fd)


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument("--execute", action="store_true")
  args = parser.parse_args()
  if os.geteuid() != 0: raise SystemExit("Root required for historical private evidence")
  try: result = execute() if args.execute else validate()[0]
  except (OSError, ValueError, KeyError) as error: raise SystemExit("Successful-v16 cleanup refused: " + str(error)) from error
  print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__": main()
