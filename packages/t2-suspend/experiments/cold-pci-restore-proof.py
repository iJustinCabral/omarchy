#!/usr/bin/python3
"""Offline contract for a future guard-assisted full image restoration runner.

Schema v1 has three independent inputs: audited ``expected`` image/stack pins,
``context`` retained by the original source process before its state=disk write,
and ``observation`` captured by that process after that SAME write returns.
Context is not a later boot's attempt.json. The future runner must construct it
in memory and call this validator from its original return path; this pure
validator cannot authenticate a JSON producer or establish process continuity.
It performs no host reads, EFI writes, witness writes, cleanup or PM operation.

Raw EFI markers establish cold restore progress, not atomic copying by
themselves. Combined with trusted original-call continuity, the unchanged source
boot and exact restored stack they support a source-return observation only.
Restore-kernel guard counters are deliberately not consulted: atomic restoration
replaces that kernel's memory. Post-cleanup health is a separate gate; neither
gate qualifies physical input, unattended cold start or usable hibernation.
Historical MBPG/pre-arch controlled-abort evidence cannot satisfy this schema.
All JSON objects have exact fields and all scalars have exact types.
"""

import hashlib
import json
import re


SCHEMA = "cold-pci-restored-source-v1"
HASH = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
SOURCE_VARIABLE = "OmarchyT2PostwriteStageV3-47a2fceb-87bc-4e58-8d83-23f62ffb3393"
RESTORE_VARIABLE = "OmarchyT2RestoreStageV2-5e17d2ad-021f-4d45-a8e5-f4c191983e27"
GUID = "5e17d2ad-021f-4d45-a8e5-f4c191983e27"
GUARD_MODULE = "mba_hibernate_cold_pci_guard"


def require(condition, message):
  if not condition:
    raise ValueError(message)


def fields(value, names, label):
  require(type(value) is dict and set(value) == set(names), label + " fields differ")


def scalar(value, kind, label, pattern=None):
  require(type(value) is kind, label + " type differs")
  if pattern is not None:
    require(pattern.fullmatch(value) is not None, label + " format differs")
  return value


def exact(actual, expected, label):
  require(type(actual) is type(expected) and actual == expected, label + " differs")


def digest(raw):
  return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
  result = {}
  for key, value in pairs:
    require(key not in result, "Duplicate JSON field: " + key)
    result[key] = value
  return result


def decode_json(raw):
  try:
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON")))
  except (UnicodeError, json.JSONDecodeError) as error:
    raise ValueError("Malformed JSON") from error


def raw_bytes(value, label):
  scalar(value, str, label)
  require(len(value) <= 2 * 1024 * 1024 and re.fullmatch(r"(?:[0-9a-f]{2})+", value) is not None,
          label + " must be bounded lowercase hex bytes")
  return bytes.fromhex(value)


def runtime(value):
  fields(value, ("kernel_release", "cmdline_sha256", "modules"), "Source runtime")
  require(type(value["kernel_release"]) is str and bool(value["kernel_release"]), "Missing kernel release")
  scalar(value["cmdline_sha256"], str, "Command line hash", HASH)
  modules = value["modules"]
  require(type(modules) is dict and bool(modules), "Missing complete source module inventory")
  for name, identity in modules.items():
    require(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_-]+", name) is not None, "Invalid module name")
    require(not name.startswith("mba_hibernate_cold_") and "abort" not in name.lower(),
            "Restore-only guard or abort module in source runtime")
    scalar(identity, str, "Module hash", HASH)


def validate_expected(expected):
  fields(expected, ("schema", "boot_id", "attempt_id", "return_nonce", "transition_vector",
                    "source_uki_sha256", "restore_uki_sha256", "production_uki_sha256",
                    "runtime_stack_sha256", "source_entry_id", "restore_entry_id",
                    "sections", "source_runtime", "guard_module_sha256",
                    "consumed_guard_sha256", "consumed_attempt_sha256", "candidate_protocol",
                    "restore_modules"), "Expected")
  exact(expected["schema"], SCHEMA, "Schema")
  exact(expected["candidate_protocol"], "cold-pci-guard-fullrestore-v1", "Fullrestore protocol")
  for key in ("boot_id", "attempt_id", "return_nonce"):
    scalar(expected[key], str, key, UUID)
  exact(expected["attempt_id"], expected["boot_id"], "Original attempt directory identity")
  for key in expected:
    if key.endswith("sha256") or key == "transition_vector":
      scalar(expected[key], str, key, HASH)
  require(expected["source_uki_sha256"] != expected["restore_uki_sha256"], "Source and restore must differ")
  vector = digest(":".join(expected[key] for key in
                  ("source_uki_sha256", "restore_uki_sha256", "runtime_stack_sha256")).encode())
  exact(expected["transition_vector"], vector, "Full pair vector")
  for role in ("source", "restore"):
    exact(expected[role + "_entry_id"], "MBA-T2-hibernation-" + role + "-" +
          expected[role + "_uki_sha256"][:16], role + " entry")
  sections = expected["sections"]
  fields(sections, ("production", "source", "restore"), "Sections")
  for role in sections:
    fields(sections[role], ("linux_sha256", "cmdline_sha256"), role + " sections")
    for key, value in sections[role].items():
      scalar(value, str, role + key, HASH)
    exact(sections[role], sections["production"], "Production .linux/.cmdline preservation")
  runtime(expected["source_runtime"])
  restore_modules = expected["restore_modules"]
  require(type(restore_modules) is dict and GUARD_MODULE in restore_modules, "Audited restore guard absent")
  for name, identity in restore_modules.items():
    require(type(name) is str and re.fullmatch(r"[a-zA-Z0-9_-]+", name) is not None, "Invalid restore module")
    require((not name.startswith("mba_hibernate_cold_") or name == GUARD_MODULE) and "abort" not in name.lower(),
            "Abort module in fullrestore candidate")
    scalar(identity, str, "Restore module hash", HASH)
  exact(restore_modules[GUARD_MODULE], expected["guard_module_sha256"], "Audited exact restore guard")
  # /proc/cmdline is a runtime pin with different byte framing from UKI .cmdline
  # (newline versus NUL), so it must not be equated to the PE section hash.


def validate_source_return(expected, observation, context):
  """Validate conditional source-return evidence; context must come from caller memory.

  ``context`` binds pins copied before the write, plus power_write_returned set
  only by the caller immediately after its original /sys/power/state write.
  ``observation.return_capture`` is retained before cleanup mutates any markers.
  Full source/restore module inventories are required, not selected counters.
  """
  validate_expected(expected)
  context_fields = ("boot_id", "attempt_id", "return_nonce", "transition_vector", "source_uki_sha256",
                    "restore_uki_sha256", "production_uki_sha256", "runtime_stack_sha256")
  fields(context, (*context_fields, "power_path", "power_value", "power_write_returned"), "Original call context")
  for key in context_fields:
    exact(context[key], expected[key], "Original call " + key)
  exact(context["power_path"], "/sys/power/state", "Power path")
  exact(context["power_value"], "disk", "Power value")
  exact(context["power_write_returned"], True, "Original power write return")
  fields(observation, ("schema", "state", "return_capture", "consumed_guard_hex", "consumed_attempt_hex",
                       "cleanup_completed", "cleanup_errors"), "Observation")
  exact(observation["schema"], SCHEMA, "Observation schema")
  exact(observation["state"], "returned-and-cleaned", "Runner final state")
  exact(observation["cleanup_completed"], True, "Cleanup completion")
  exact(observation["cleanup_errors"], [], "Cleanup errors")
  guard = raw_bytes(observation["consumed_guard_hex"], "Consumed guard")
  exact(guard, (expected["boot_id"] + "\n").encode(), "Consumed guard original boot")
  exact(digest(guard), expected["consumed_guard_sha256"], "Consumed guard hash")
  attempt_raw = raw_bytes(observation["consumed_attempt_hex"], "Consumed attempt")
  exact(digest(attempt_raw), expected["consumed_attempt_sha256"], "Consumed attempt hash")
  attempt = decode_json(attempt_raw)
  require(type(attempt) is dict, "Attempt is not an object")
  for key in ("boot_id", "transition_vector", "source_uki_sha256", "restore_uki_sha256", "runtime_stack_sha256",
              "source_entry_id", "restore_entry_id"):
    exact(attempt.get(key), expected[key], "Consumed attempt " + key)
  for key, value in {"state": "transition-armed", "hibernate_attempted": True,
                     "real_s4_attempted": True, "hardware_qualified": False,
                     "requested_disk_mode": "platform"}.items():
    exact(attempt.get(key), value, "Consumed attempt " + key)
  require(not attempt.get("error") and not attempt.get("cleanup_errors"), "Failed consumed attempt")
  capture = observation["return_capture"]
  fields(capture, ("context", "state", "boot_id", "LoaderEntrySelected_hex", "efi_overrides",
                   "pair_pins", "runtime_stack_sha256", "source_runtime", "markers",
                   "restore_only_modules", "abort_modules", "abort_witnesses"), "Immediate return capture")
  exact(capture["context"], context, "Return context")
  # Deep scalar types must also match (Python True == 1 is insufficient).
  for key, value in context.items():
    exact(capture["context"][key], value, "Captured context " + key)
  exact(capture["state"], "returned", "Original runner return state")
  exact(capture["boot_id"], expected["boot_id"], "Restored original source boot")
  selected = b"\x06\0\0\0" + (expected["restore_entry_id"] + "\0").encode("utf-16-le")
  exact(raw_bytes(capture["LoaderEntrySelected_hex"], "Selected entry"), selected, "Exact cold restore selection")
  exact(capture["efi_overrides"], {"LoaderEntryOneShot": None, "LoaderEntryDefault": None}, "EFI overrides")
  for key, value in capture["efi_overrides"].items():
    exact(value, None, key)
  pins = ("source_uki_sha256", "restore_uki_sha256", "production_uki_sha256", "runtime_stack_sha256",
          "guard_module_sha256", "sections", "candidate_protocol", "restore_modules")
  fields(capture["pair_pins"], pins, "Observed pair pins")
  for key in pins:
    exact(capture["pair_pins"][key], expected[key], "Observed " + key)
  exact(capture["runtime_stack_sha256"], expected["runtime_stack_sha256"], "Restored source stack")
  runtime(capture["source_runtime"])
  exact(capture["source_runtime"], expected["source_runtime"], "Exact restored source runtime inventory")
  exact(capture["restore_only_modules"], [], "Restore-only modules must be absent")
  exact(capture["abort_modules"], [], "All abort modules must be absent")
  exact(capture["abort_witnesses"], [], "Current-vector controlled-abort witnesses must be absent")
  vector = expected["transition_vector"]
  marker_specs = {SOURCE_VARIABLE: (b"MBPW", bytes.fromhex(vector[:24]), 4),
                  RESTORE_VARIABLE: (b"MBRS", bytes.fromhex(vector[:24]), 7),
                  "OmarchyT2RestoreHookEntered" + vector[:24] + "-" + GUID: (b"MBRH", vector[:24].encode(), 1),
                  "OmarchyT2RestoreHookArmed" + vector[:24] + "-" + GUID: (b"MBRH", vector[:24].encode(), 2)}
  fields(capture["markers"], marker_specs, "Exclusive fullrestore markers")
  for name, (magic, token, stage) in marker_specs.items():
    exact(raw_bytes(capture["markers"][name], name), b"\x07\0\0\0" + magic + token + bytes((stage,)), name)
  return {"schema": SCHEMA, "classification": "source-return-evidence-valid",
          "boot_id": expected["boot_id"], "transition_vector": vector,
          "return_nonce": expected["return_nonce"], "hardware_qualified": False,
          "physical_input_confirmed": False, "usable_hibernation_qualified": False}


def validate_post_cleanup(expected, observation, context, health):
  """Additional health gate, with no physical input or usability qualification.

  devices.internal_keyboard/internal_trackpad attest enumeration only, never
  observed key presses, pointer movement or restored input functionality.
  """
  proof = validate_source_return(expected, observation, context)
  fields(health, ("boot_id", "transition_vector", "return_nonce", "after_cleanup", "devices",
                  "services", "failed_units", "pm"), "Post-cleanup health")
  for key in ("boot_id", "transition_vector", "return_nonce"):
    exact(health[key], expected[key], "Health " + key)
  exact(health["after_cleanup"], True, "Health sampling order")
  exact(health["failed_units"], [], "Failed services")
  devices = {"primary_encrypted_root": True, "internal_keyboard": True,
             "internal_trackpad": True, "wifi": True, "bluetooth": True, "ac_online": True}
  services = {"NetworkManager.service": "active", "bluetooth.service": "active", "sddm.service": "active"}
  pm = {"pm_test": "none", "disk": "platform", "pm_trace": "0",
        "resume_device": "/dev/mapper/root", "resume_offset": 1923214}
  for key, contract in (("devices", devices), ("services", services), ("pm", pm)):
    fields(health[key], contract, "Healthy " + key)
    for name, value in contract.items():
      exact(health[key][name], value, "Health " + name)
  return {**proof, "post_cleanup_health_valid": True}
