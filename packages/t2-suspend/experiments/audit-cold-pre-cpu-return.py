#!/usr/bin/python3
"""Read-only, fail-closed audit of a private cold pre-CPU controlled return.

This does not execute, qualify, clean up, or retry a hibernation transition.
The returned witness proves the intentionally aborting restore kernel returned
to its initramfs, not atomic restoration or resumed source userspace.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("cold_return_pair", HERE / "stage-hibernation-uki-pair.py")
PAIR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PAIR)
COLD = PAIR.AUDIT.COLD
HASH = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
GUID = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"
EFI = Path("sys/firmware/efi/efivars")
SOURCE_VARIABLE = "OmarchyT2PostwriteStageV3-47a2fceb-87bc-4e58-8d83-23f62ffb3393"
RESTORE_VARIABLE = "OmarchyT2RestoreStageV2-" + GUID
SOURCE_MODULE_SHA256 = "4cbe981d7ad945d65057b286feb069d569aeaef93ac08d2a0fba4fcb220bcd28"
SOURCE_MODULE_SRCVERSION = "1A72ABF3A3BFC778FC5A9C6"
ATTRIBUTES = b"\x07\0\0\0"
LOADER_ATTRIBUTES = b"\x06\0\0\0"
ATTEMPT_STATES = {"preparing", "isolated", "guard-consumed", "postwrite-efi-marker-armed",
                  "restore-entry-armed", "transition-armed", "returned", "transition-failed",
                  "guard-consumed-pretransition-failure", "preflight-cleanup", "cleanup-failed", "returned-and-cleaned"}


def sha256(data):
  return hashlib.sha256(data).hexdigest()


def exact_hash(value, description):
  if not isinstance(value, str) or HASH.fullmatch(value) is None:
    raise ValueError(description + " is not an exact SHA-256")
  return value


def exact_uuid(value, description):
  if not isinstance(value, str) or UUID.fullmatch(value) is None:
    raise ValueError(description + " is not an exact boot ID")
  return value


class Snapshot:
  """No-follow evidence reads with a final unchanged-snapshot check."""

  def __init__(self, root):
    self.root = Path(root).resolve()
    self.uid = 0 if self.root == Path("/") else os.geteuid()
    self.files = {}

  def path(self, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
      raise ValueError("Evidence path escapes root")
    path = self.root / relative
    for parent in (path, *path.parents):
      if parent == self.root:
        break
      if parent.is_symlink():
        raise ValueError("Symlinked evidence: " + str(relative))
    return path

  def read(self, relative, private=False, optional=False):
    path = self.path(relative)
    try:
      descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
      if not optional:
        raise ValueError("Missing evidence: " + str(relative)) from None
      self.files[Path(relative)] = (None, private)
      return None
    try:
      metadata = os.fstat(descriptor)
      if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("Nonregular evidence: " + str(relative))
      if private and (metadata.st_uid != self.uid or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise ValueError("Unsafe private evidence owner or mode: " + str(relative))
      with os.fdopen(descriptor, "rb", closefd=False) as stream:
        raw = stream.read(1024 * 1024 + 1)
      if len(raw) > 1024 * 1024:
        raise ValueError("Oversized evidence: " + str(relative))
    finally:
      os.close(descriptor)
    self.files[Path(relative)] = (raw, private)
    return raw

  def json(self, relative, optional=False):
    raw = self.read(relative, private=True, optional=optional)
    if raw is None:
      return None
    def unique(pairs):
      result = {}
      for key, value in pairs:
        if key in result:
          raise ValueError("Duplicate JSON evidence field: " + key)
        result[key] = value
      return result
    try:
      data = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError) as error:
      raise ValueError("Malformed JSON evidence: " + str(relative)) from error
    if not isinstance(data, dict):
      raise ValueError("Nonobject JSON evidence: " + str(relative))
    return data

  def finish(self):
    original = dict(self.files)
    for relative, (raw, private) in original.items():
      if self.read(relative, private=private, optional=raw is None) != raw:
        raise ValueError("Evidence changed during audit: " + str(relative))
    return {str(path): sha256(raw) if raw is not None else None for path, (raw, _) in original.items()}


def require_fields(record, expected, description):
  for key, value in expected.items():
    if key not in record or type(record[key]) is not type(value) or record[key] != value:
      raise ValueError(description + " mismatch: " + key)


def marker(snapshot, name, magic, vector, maximum, ascii_prefix=False, exact_stage=None):
  raw = snapshot.read(EFI / name, optional=True)
  if raw is None:
    return {"present": False, "matching_vector": False, "stage": None, "sha256": None}
  length = 24 if ascii_prefix else 12
  if len(raw) != 9 + length or raw[:4] != ATTRIBUTES or raw[4:8] != magic:
    raise ValueError("Malformed EFI marker: " + name)
  token = raw[8:-1]
  if ascii_prefix:
    try:
      prefix = token.decode("ascii")
    except UnicodeError as error:
      raise ValueError("Malformed ASCII EFI marker prefix: " + name) from error
    if re.fullmatch(r"[0-9a-f]{24}", prefix) is None:
      raise ValueError("Malformed ASCII EFI marker prefix: " + name)
  else:
    prefix = token.hex()
  stage = raw[-1]
  if stage > maximum or (exact_stage is not None and stage != exact_stage):
    raise ValueError("Invalid EFI marker stage: " + name)
  if ascii_prefix and prefix != vector[:24]:
    raise ValueError("Conflicting vector-bound EFI marker: " + name)
  return {"present": True, "matching_vector": prefix == vector[:24], "vector_prefix": prefix,
          "stage": stage, "sha256": sha256(raw)}


def attempt_names(snapshot, directory):
  path = snapshot.path(directory)
  if not path.exists():
    return []
  if not path.is_dir():
    raise ValueError("Attempt archive is not a directory")
  names = sorted(child.name for child in path.iterdir())
  for name in names:
    exact_uuid(name, "Archived attempt name")
    if not snapshot.path(directory / name).is_dir():
      raise ValueError("Archived attempt is not a directory")
  if len(names) > 1:
    raise ValueError("Multiple attempts for one consumed pair vector")
  return names


def inspect(root, source, restore, expected_pair_vector, pair_loader=PAIR.load_pair, staged_verifier=PAIR.verify_staged,
            required_protocol="cold_pre_cpu"):
  vector = exact_hash(expected_pair_vector, "Expected pair vector")
  snapshot = Snapshot(root)
  receipt = snapshot.json(PAIR.RECEIPT)
  pair, images, _ = pair_loader(Path(source), Path(restore))
  protocol = COLD.select(pair)
  if protocol != required_protocol or protocol not in COLD.PROFILES:
    raise ValueError("Restore provenance does not identify the requested cold abort protocol")
  profile = COLD.PROFILES[protocol]
  if not isinstance(pair.get(protocol), dict) or pair[protocol].get("version") != profile["version"]:
    raise ValueError("Restore provenance does not identify the exact cold abort diagnostic")
  if profile["observations"] is not None:
    observed = pair[protocol].get("boundary_observations")
    if (not isinstance(observed, dict) or observed != profile["observations"] or
        any(type(observed[key]) is not type(value) for key, value in profile["observations"].items())):
      raise ValueError("Cold abort returned proof lacks its exact observation contract")
  restore_marker = pair.get("restore_marker")
  if not isinstance(restore_marker, dict) or restore_marker.get("version") != "v2" or restore_marker.get("efi_variable") != RESTORE_VARIABLE:
    raise ValueError("Restore provenance does not identify the V2 stage marker")
  runtime = exact_hash(pair.get("runtime_stack_sha256"), "Runtime stack")
  image_hashes = [exact_hash(images[role]["sha256"], role + " UKI") for role in ("source", "restore")]
  actual_vector = sha256((":".join(image_hashes + [runtime])).encode())
  if actual_vector != vector:
    raise ValueError("Expected full pair vector differs from the audited private pair")
  require_fields(receipt, {"kernel_policy": "production-linux-unchanged", "runtime_stack_sha256": runtime}, "Receipt")
  if receipt.get("state") not in ("source-arming", "restore-arming"):
    raise ValueError("Receipt is not a source/restore armed pair transaction")
  for role in ("source", "restore"):
    metadata = receipt.get("images", {}).get(role)
    if not isinstance(metadata, dict):
      raise ValueError("Missing receipt image: " + role)
    require_fields(metadata, {key: images[role][key] for key in ("sha256", "blake2", "provenance_sha256", "experiment_id")}, role + " receipt")
    require_fields(metadata, {"entry_id": PAIR.entry_id(role, images[role]["sha256"])}, role + " receipt")
  staged_verifier(snapshot.root, receipt)
  current_boot = exact_uuid(snapshot.read(PAIR.BOOT_ID).decode().strip(), "Current boot")
  selected_raw = snapshot.read(PAIR.SINGLE.SELECTED)
  try:
    if len(selected_raw) < 6 or selected_raw[:4] != LOADER_ATTRIBUTES or len(selected_raw) % 2:
      raise ValueError("Malformed selected EFI entry")
    selected = selected_raw[4:].decode("utf-16-le").rstrip("\0")
  except UnicodeError as error:
    raise ValueError("Malformed selected EFI entry") from error
  directory = PAIR.STATE / "s4-vectors" / vector
  attempts = directory / "attempts"
  names = attempt_names(snapshot, attempts)
  guard_raw = snapshot.read(directory / "s4-attempted", private=True, optional=True)
  guard_boot = None
  if guard_raw is not None:
    try:
      guard_boot = exact_uuid(guard_raw.decode().removesuffix("\n"), "Consumed guard")
      if guard_raw != (guard_boot + "\n").encode():
        raise ValueError("Malformed consumed guard encoding")
    except UnicodeError as error:
      raise ValueError("Malformed consumed guard") from error
  source_boot = names[0] if names else guard_boot
  if guard_boot is not None and names and source_boot != guard_boot:
    raise ValueError("Consumed guard differs from archived attempt boot")
  record = snapshot.json(attempts / source_boot / "attempt.json", optional=True) if names else None
  identities = {}
  if record is not None:
    expected = {"boot_id": source_boot, "candidate_uki_sha256": image_hashes[0],
                "entry_id": receipt["images"]["source"]["entry_id"],
                "source_entry_id": receipt["images"]["source"]["entry_id"],
                "restore_entry_id": receipt["images"]["restore"]["entry_id"],
                "source_uki_sha256": image_hashes[0], "restore_uki_sha256": image_hashes[1],
                "runtime_stack_sha256": runtime, "transition_vector": vector,
                "hardware_qualified": False, "recovery_method": "operator-attended-cold-power"}
    require_fields(record, expected, "Attempt")
    if (type(record.get("hibernate_attempted")) is not bool or
        type(record.get("real_s4_attempted")) is not bool or
        record["hibernate_attempted"] != record["real_s4_attempted"]):
      raise ValueError("Conflicting attempt transition flags")
    if not isinstance(record.get("state"), str) or record["state"] not in ATTEMPT_STATES:
      raise ValueError("Malformed attempt state")
    if record["state"] == "transition-armed" and not record["real_s4_attempted"]:
      raise ValueError("Transition-armed state contradicts attempt flags")
    if record["real_s4_attempted"] and guard_boot is None:
      raise ValueError("Attempted transition lacks its consumed guard")
    for kind in ("postwrite", "restore"):
      filename = attempts / source_boot / (kind + "-efi-identity.json")
      identity = snapshot.json(filename, optional=True)
      identities[kind] = identity
      if identity is not None:
        expected = {"kind": kind + "-efi-s4-identity-v1", "vector": vector,
                    "source_boot_id": source_boot, "source_efi_variable": SOURCE_VARIABLE}
        if kind == "postwrite":
          expected.update(module_sha256=SOURCE_MODULE_SHA256, module_srcversion=SOURCE_MODULE_SRCVERSION,
                          recovery="operator-attended-cold-power")
        else:
          expected.update(module_sha256=restore_marker["sha256"], module_srcversion=restore_marker["srcversion"],
                          efi_variable=RESTORE_VARIABLE)
        if identity != expected:
          raise ValueError("Conflicting " + kind + " prearm identity")
  markers = {
    "source": marker(snapshot, SOURCE_VARIABLE, b"MBPW", vector, 4),
    "restore": marker(snapshot, RESTORE_VARIABLE, b"MBRS", vector, 7),
  }
  for kind, stage in (("entered", 1), ("armed", 2), ("returned", 1)):
    name = (profile["returned"] if kind == "returned" else "OmarchyT2RestoreHook" + kind.capitalize()) + vector[:24] + "-" + GUID
    markers[kind] = marker(snapshot, name, profile["magic"] if kind == "returned" else b"MBRH", vector, stage,
                           ascii_prefix=True, exact_stage=stage)
  for key, other in COLD.PROFILES.items():
    if key != protocol:
      conflicting = marker(snapshot, other["returned"] + vector[:24] + "-" + GUID, other["magic"], vector, 1,
                           ascii_prefix=True, exact_stage=1)
      if conflicting["present"]:
        raise ValueError("Cross-protocol returned witness is forbidden")
  matching = lambda kind: markers[kind]["present"] and markers[kind]["matching_vector"]
  if markers["armed"]["present"] and not markers["entered"]["present"]:
    raise ValueError("Armed witness without entered witness")
  has_attempt = bool(names) or guard_boot is not None
  if has_attempt and any(markers[kind]["present"] and not matching(kind) for kind in ("source", "restore")):
    raise ValueError("Global stage marker conflicts with this attempted vector")
  any_current_marker = any(matching(kind) for kind in markers)
  if not has_attempt and any_current_marker:
    raise ValueError("Current-vector EFI evidence without an archived attempt")
  complete_attempt = (record is not None and guard_boot is not None and record["real_s4_attempted"] and
                      record["state"] == "transition-armed" and all(identities.values()))
  complete_markers = (matching("source") and markers["source"]["stage"] == 4 and
                      matching("restore") and markers["restore"]["stage"] == 7 and
                      matching("entered") and matching("armed"))
  result = "never-attempted" if not has_attempt else "incomplete-attempt"
  if complete_attempt:
    require_fields(receipt, {"state": "restore-arming", "restore_armed_from_boot_id": source_boot}, "Consumed restore receipt")
    require_fields(record, {"requested_disk_mode": "platform", "qualification": "pair-source-ordinary-boot-preflight-passed"}, "Controlled attempt")
    if record.get("cleanup_errors") or record.get("error"):
      raise ValueError("Controlled attempt records errors")
    if complete_markers:
      result = "return-witness-missing"
  if markers["returned"]["present"]:
    if not complete_attempt or not complete_markers:
      raise ValueError("Returned witness lacks the exact consumed attempt and stage/hook evidence")
    if current_boot == source_boot or selected != "Omarchy.linux-t2":
      raise ValueError("Recovered witness requires a distinct current stock return boot")
    for relative in (PAIR.SINGLE.ONESHOT, PAIR.SINGLE.DEFAULT):
      if snapshot.read(relative, optional=True) is not None:
        raise ValueError("Recovered stock return retains an EFI boot override")
    result = "controlled-abort-return"
  if attempt_names(snapshot, attempts) != names:
    raise ValueError("Attempt archive changed during audit")
  evidence_hashes = snapshot.finish()
  return {
    "classification": result, "pair_vector": vector,
    "hibernate_success": False, "restored_userspace": False, "hardware_qualified": False,
    "source_boot_id": source_boot or (current_boot if selected == receipt["images"]["source"]["entry_id"] else None),
    "attempt_source_boot_id": source_boot, "current_boot_id": current_boot, "current_entry_id": selected,
    "return_boot_id": current_boot if result == "controlled-abort-return" else None,
    "guard_consumed": guard_boot is not None, "attempt_state": record.get("state") if record else None,
    "real_s4_attempted": record.get("real_s4_attempted") if record else False,
    "images": {role: {key: images[role][key] for key in ("sha256", "provenance_sha256", "experiment_id")} for role in images},
    "runtime_stack_sha256": runtime, protocol: pair[protocol], "protocol": profile["version"],
    "boundary": profile["target"], "witness_attested_observations": profile["observations"] if result == "controlled-abort-return" else None,
    "markers": markers, "evidence_sha256": evidence_hashes,
    "restore_stage_7_semantics": "dpm_suspend_end entry only; no proof of noirq or atomic restore completion",
    "controlled_return_semantics": "exclusive witness of intentional " + profile["target"] + " entry abort recovery to restore initramfs; not restored source userspace or completion of target body",
  }


def main(required_protocol="cold_pre_cpu"):
  profile = COLD.PROFILES[required_protocol]
  parser = argparse.ArgumentParser(description="Read-only " + profile["version"] + " controlled-return audit; never proof of atomic restoration or successful hibernation.")
  parser.add_argument("--source", type=Path, required=True)
  parser.add_argument("--restore", type=Path, required=True)
  parser.add_argument("--expected-pair-vector", required=True)
  arguments = parser.parse_args()
  if os.geteuid() != 0:
    parser.error("Read-only host evidence audit requires root")
  try:
    result = inspect(Path("/"), arguments.source, arguments.restore, arguments.expected_pair_vector, required_protocol=required_protocol)
  except (ValueError, OSError, KeyError, TypeError) as error:
    parser.exit(1, required_protocol.replace("_", "-") + "-return audit refused: " + str(error) + "\n")
  print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
  main()
