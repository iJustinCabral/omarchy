#!/usr/bin/python3
"""Original-process fullrestore collector; never a later-boot proof importer.

Only the source runner calls this, around its original state=disk write. Module
file hashes are conditional identities: loaded sysfs srcversions must match the
selected files. They cannot authenticate the bytes of arbitrary kernel memory.
No CLI is provided, and no EFI, module or power operation is performed here.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import uuid


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("fullrestore_proof", HERE / "cold-pci-restore-proof.py")
PROOF = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROOF)
PROTOCOL = "cold-pci-guard-fullrestore-v1"
EFI = Path("sys/firmware/efi/efivars")
LOADER_GUID = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
PIN_KEYS = ("source_uki_sha256", "restore_uki_sha256", "production_uki_sha256",
            "runtime_stack_sha256", "guard_module_sha256", "sections", "candidate_protocol", "restore_modules")


def command(arguments):
  return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout.strip()


def path(root, relative):
  result = Path(root) / relative
  result.resolve().relative_to(Path(root).resolve())
  return result


def raw(root, relative):
  target = path(root, relative)
  if target.is_symlink() or not target.is_file():
    raise ValueError("Missing or symlinked fullrestore evidence: " + str(relative))
  return target.read_bytes()


def private_new(pathname, value):
  """Exclusive private durable evidence, preserving any existing witness."""
  data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
  descriptor = os.open(pathname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
  with os.fdopen(descriptor, "wb") as stream:
    stream.write(data)
    stream.flush()
    os.fsync(stream.fileno())
  descriptor = os.open(pathname.parent, os.O_RDONLY | os.O_DIRECTORY)
  try:
    os.fsync(descriptor)
  finally:
    os.close(descriptor)
  metadata = pathname.stat()
  if pathname.is_symlink() or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or pathname.read_bytes() != data:
    raise ValueError("Private fullrestore evidence readback differs: " + pathname.name)


def runtime_inventory(root, provenance, backend, query=command, source_tree=None):
  """Inventory every /proc/modules entry, independently of expected identities."""
  names = [line.split()[0] for line in raw(root, "proc/modules").decode().splitlines()]
  if not names or len(names) != len(set(names)):
    raise ValueError("Empty or duplicate loaded module inventory")
  inventory = {}
  pins = {name.replace("-", "_"): metadata for name, metadata in provenance["modules"].items()}
  originals = {name.replace("-", "_"): name for name in provenance["modules"]}
  sys_names = {item.name for item in path(root, "sys/module").iterdir()}
  forbidden = [name for name in sys_names if name.startswith("mba_hibernate_cold_") or "abort" in name.lower() or name == "mba_hibernate_efi_restore_marker"]
  if forbidden:
    raise ValueError("Restore-only or abort module in original source inventory: " + ", ".join(sorted(forbidden)))
  for name in names:
    if name.startswith("mba_hibernate_cold_") or "abort" in name.lower() or name == "mba_hibernate_efi_restore_marker":
      raise ValueError("Restore-only or abort module in original source inventory: " + name)
    if name == "mba_hibernate_efi_postwrite_marker":
      selected_path = backend.module_path
    elif name in pins:
      # Source T2/Wi-Fi drivers load early from its exact private initramfs.
      # Only Bluetooth is copied into /run by the source Bluetooth latehook.
      if source_tree is None:
        raise ValueError("Exact source initramfs extraction required")
      relative = provenance["initrd_module_selection"].get(originals[name])
      if not isinstance(relative, str) or not relative.startswith("usr/lib/modules/"):
        raise ValueError("Source initramfs module selection absent: " + name)
      embedded_path = path(source_tree, relative)
      if embedded_path.is_symlink() or not embedded_path.is_file():
        raise ValueError("Source initramfs selected module missing or symlinked: " + name)
      if hashlib.sha256(embedded_path.read_bytes()).hexdigest() != pins[name]["sha256"]:
        raise ValueError("Actual source initramfs module differs from audited hash: " + name)
      selected_path = path(root, "run/omarchy-t2-hibernation-candidate/hci_bcm4377.ko") if name == "hci_bcm4377" else embedded_path
    else:
      # Ordinary production modules may omit srcversion. Their names belong to
      # the complete inventory; hash identities apply to the audited T2 stack.
      continue
    if selected_path.is_symlink() or not selected_path.is_file():
      raise ValueError("Selected module file missing or symlinked: " + name)
    loaded_version = raw(root, Path("sys/module") / name / "srcversion").decode().strip()
    file_version = query(("modinfo", "-F", "srcversion", str(selected_path)))
    if not loaded_version or loaded_version != file_version:
      raise ValueError("Loaded module differs from selected file: " + name)
    identity = hashlib.sha256(selected_path.read_bytes()).hexdigest()
    if name in pins and (identity != pins[name]["sha256"] or loaded_version != pins[name]["srcversion"]):
      raise ValueError("Observed candidate module differs from audited pin: " + name)
    if name == "mba_hibernate_efi_postwrite_marker" and (identity != backend.expected_sha256 or loaded_version != backend.expected_srcversion):
      raise ValueError("Observed source marker differs from backend pin")
    inventory[name] = identity
  required = {"brcmfmac", "brcmfmac_wcc", "hci_bcm4377", "t2bce_dma", "t2bce_core", "t2bce_vhci", "t2bce_audio"}
  if not required.issubset(inventory):
    raise ValueError("Mandatory audited source stack is incomplete")
  release = raw(root, "proc/sys/kernel/osrelease").decode().strip()
  cmdline = raw(root, "proc/cmdline")
  if release != provenance["kernel_release"] or cmdline.decode().strip() != provenance["cmdline"]:
    raise ValueError("Observed kernel or command line differs from source provenance")
  if "mba_hibernate_efi_postwrite_marker" not in inventory:
    raise ValueError("Original source marker missing from inventory")
  return {"kernel_release": release, "cmdline_sha256": hashlib.sha256(cmdline).hexdigest(),
          "modules": inventory, "loaded_modules": sorted(names)}


class Collector:
  def __init__(self, root, source_directory, restore_directory, evidence, backend, pair, stack_identity,
               inventory=runtime_inventory, query=command):
    self.root = Path(root)
    self.source_directory = Path(source_directory)
    self.restore_directory = Path(restore_directory)
    self.evidence = copy.deepcopy(evidence)
    self.backend = backend
    self.pair = pair
    self.stack_identity = stack_identity
    self.inventory = inventory
    self.query = query
    self.context = None
    self.capture = None
    self.expected = None

  def pins(self):
    receipt = self.pair.load_receipt(self.root)
    self.pair.verify_staged(self.root, receipt)
    source = self.pair.AUDIT.load_candidate(self.source_directory, "source")
    restore = self.pair.AUDIT.load_candidate(self.restore_directory, "restore")
    audited = self.pair.AUDIT.audit(source, restore)
    metadata = restore.get("cold_pci_restore")
    if not isinstance(metadata, dict) or metadata.get("version") != PROTOCOL:
      raise ValueError("Candidate lacks exact audited fullrestore protocol")
    sections = {}
    for role, provenance in (("source", source), ("restore", restore)):
      self.pair.require_production_kernel(provenance, role)
      preserved = provenance["unchanged_production_sections_sha256"]
      sections[role] = {"linux_sha256": preserved[".linux"], "cmdline_sha256": preserved[".cmdline"]}
      image = receipt["images"][role]
      if image["sha256"] != provenance["candidate_uki_sha256"] or image["provenance_sha256"] != self.pair.digest((self.source_directory if role == "source" else self.restore_directory) / "provenance.json"):
        raise ValueError("Staged pair differs from audited private provenance")
    sections["production"] = copy.deepcopy(sections["source"])
    restore_modules = {name: item["sha256"] for name, item in restore["modules"].items()}
    restore_modules[PROOF.GUARD_MODULE] = metadata["guard_module_sha256"]
    restore_modules["mba_hibernate_efi_restore_marker"] = restore["restore_marker"]["sha256"]
    return {"source_uki_sha256": audited["source_uki_sha256"], "restore_uki_sha256": audited["restore_uki_sha256"],
            "production_uki_sha256": receipt["production_uki_sha256"], "runtime_stack_sha256": audited["runtime_stack_sha256"],
            "guard_module_sha256": metadata["guard_module_sha256"], "sections": sections,
            "candidate_protocol": metadata["version"], "restore_modules": restore_modules}, source

  def before_write(self, guard, attempt, attempt_directory):
    if self.context is not None:
      raise ValueError("Fullrestore original call context already exists")
    pins, source = self.pins()
    self.guard_raw = raw(self.root, guard.relative_to(self.root))
    self.attempt_raw = raw(self.root, attempt.relative_to(self.root))
    self.directory = attempt_directory
    self.expected = {**pins, "schema": PROOF.SCHEMA, "boot_id": self.evidence["boot_id"],
                     "attempt_id": self.evidence["boot_id"], "return_nonce": str(uuid.uuid4()),
                     "transition_vector": self.evidence["transition_vector"],
                     "source_entry_id": self.evidence["source_entry_id"], "restore_entry_id": self.evidence["restore_entry_id"],
                     "consumed_guard_sha256": PROOF.digest(self.guard_raw), "consumed_attempt_sha256": PROOF.digest(self.attempt_raw),
                     "source_runtime": self.sample_runtime(source)}
    PROOF.validate_expected(self.expected)
    self.context = {key: self.expected[key] for key in ("boot_id", "attempt_id", "return_nonce", "transition_vector",
                    "source_uki_sha256", "restore_uki_sha256", "production_uki_sha256", "runtime_stack_sha256")}
    self.context.update(power_path="/sys/power/state", power_value="disk", power_write_returned=False)
    private_new(self.directory / "cold-pci-restore-context.json", {"expected": self.expected, "context": self.context})

  def sample_runtime(self, source):
    with tempfile.TemporaryDirectory(prefix="t2-fullrestore-source-modules-") as temporary:
      tree = Path(temporary)
      self.pair.AUDIT.extract_restore_initramfs(self.source_directory / "mba-t2-hibernation-candidate.initrd", tree)
      return self.inventory(self.root, source, self.backend, self.query, tree)

  def returned(self):
    if self.context is None or self.capture is not None:
      raise ValueError("No original fullrestore write context, or duplicate return")
    self.context["power_write_returned"] = True
    # Raw bytes first: retain them even if a subsequent audit/inventory read fails.
    vector = self.expected["transition_vector"]
    names = (PROOF.SOURCE_VARIABLE, PROOF.RESTORE_VARIABLE,
             "OmarchyT2RestoreHookEntered" + vector[:24] + "-" + PROOF.GUID,
             "OmarchyT2RestoreHookArmed" + vector[:24] + "-" + PROOF.GUID)
    read_errors = []
    def capture_raw(relative):
      try:
        return raw(self.root, relative).hex()
      except (OSError, ValueError) as error:
        read_errors.append(str(error))
        return None
    markers = {name: capture_raw(EFI / name) for name in names}
    selected = capture_raw(EFI / ("LoaderEntrySelected-" + LOADER_GUID))
    overrides = {}
    for name in ("LoaderEntryOneShot", "LoaderEntryDefault"):
      target = self.root / EFI / (name + "-" + LOADER_GUID)
      overrides[name] = capture_raw(target.relative_to(self.root)) if target.exists() or target.is_symlink() else None
    boot_raw = capture_raw("proc/sys/kernel/random/boot_id")
    boot_id = bytes.fromhex(boot_raw).decode().strip() if boot_raw is not None else None
    abort_witnesses = sorted(item.name for item in path(self.root, EFI).iterdir()
                             if "Returned" in item.name and "OmarchyT2Cold" in item.name and vector[:24] in item.name)
    initial = {"context": copy.deepcopy(self.context), "markers": markers, "LoaderEntrySelected_hex": selected,
               "efi_overrides": overrides, "boot_id": boot_id, "abort_witnesses": abort_witnesses}
    private_new(self.directory / "cold-pci-restore-return-raw.json", {**initial, "read_errors": read_errors})
    if read_errors:
      raise ValueError("Incomplete original fullrestore return capture: " + "; ".join(read_errors))
    pins, source = self.pins()
    runtime = self.sample_runtime(source)
    names = runtime["modules"]
    self.capture = {**initial, "state": "returned", "pair_pins": pins,
                    "runtime_stack_sha256": self.stack_identity(source), "source_runtime": runtime,
                    "restore_only_modules": sorted(name for name in names if name.startswith("mba_hibernate_cold_") or name == "mba_hibernate_efi_restore_marker"),
                    "abort_modules": sorted(name for name in names if "abort" in name.lower())}
    private_new(self.directory / "cold-pci-restore-return.json", self.capture)

  def health(self):
    root = self.root
    devices = self.pair.AUDIT.S4.VERIFIER.verify_devices(root)
    self.pair.AUDIT.S4.VERIFIER.verify_pci(root)
    mounts = raw(root, "proc/self/mounts").decode().splitlines()
    primary = [line.split() for line in mounts if len(line.split()) >= 4 and line.split()[1] == "/"]
    ac = [item for item in path(root, "sys/class/power_supply").glob("*/online")
          if (item.parent / "type").is_file() and (item.parent / "type").read_text().strip() == "Mains"]
    services = {name: self.query(("systemctl", "is-active", name)) for name in ("NetworkManager.service", "bluetooth.service", "sddm.service")}
    failed = self.query(("systemctl", "--failed", "--no-legend", "--plain", "--no-pager")).splitlines()
    selected = lambda name: next((word[1:-1] for word in raw(root, "sys/power/" + name).decode().split() if word.startswith("[") and word.endswith("]")), "")
    resume = raw(root, "sys/power/resume").decode().strip()
    devnum = self.query(("lsblk", "--nodeps", "--noheadings", "--output", "MAJ:MIN", "/dev/mapper/root"))
    return {**{key: self.expected[key] for key in ("boot_id", "transition_vector", "return_nonce")},
            "boot_id": raw(root, "proc/sys/kernel/random/boot_id").decode().strip(), "after_cleanup": True,
            "devices": {"primary_encrypted_root": len(primary) == 1 and primary[0][0] == "/dev/mapper/root" and primary[0][2] == "btrfs" and "subvol=/@" in primary[0][3].split(","),
                        "internal_keyboard": devices["internal_input_interfaces"] >= 2, "internal_trackpad": devices["internal_input_interfaces"] >= 2,
                        "wifi": bool(devices["wifi_interfaces"]), "bluetooth": devices["bluetooth_controller"] == "hci0",
                        "ac_online": any(item.read_text().strip() == "1" for item in ac)},
            "services": services, "failed_units": failed,
            "pm": {"pm_test": selected("pm_test"), "disk": selected("disk"), "pm_trace": raw(root, "sys/power/pm_trace").decode().strip(),
                   "resume_device": "/dev/mapper/root" if resume == devnum else resume,
                   "resume_offset": int(raw(root, "sys/power/resume_offset").decode().strip())}}

  def finish(self, cleanup_errors):
    if self.capture is None:
      raise ValueError("Missing immediate original source return capture")
    observation = {"schema": PROOF.SCHEMA, "state": "returned-and-cleaned", "return_capture": self.capture,
                   "consumed_guard_hex": self.guard_raw.hex(), "consumed_attempt_hex": self.attempt_raw.hex(),
                   "cleanup_completed": not cleanup_errors, "cleanup_errors": cleanup_errors}
    private_new(self.directory / "cold-pci-restore-observation.json", observation)
    health = self.health()
    private_new(self.directory / "cold-pci-restore-health.json", health)
    proof = PROOF.validate_post_cleanup(self.expected, observation, self.context, health)
    witness = {"expected": self.expected, "observation": observation, "health": health, "proof": proof,
               "continuity": "conditional-on-trusted-original-source-runner-process"}
    private_new(self.directory / "cold-pci-restored-source-witness.json", witness)
    return proof
