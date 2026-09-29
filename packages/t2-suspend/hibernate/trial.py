"""Explicit one-use trial dispatcher, not a service or product qualification.

Import/help/check never execute preparation or power operations. Live execution
has fixed root-private state, no alternate root/guard/config CLI flags, and must
be explicitly invoked as root. Injected execute() exists for synthetic tests.
External authorization and physical acceptance are not authored by this code.
"""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


TX = _module("trial_transaction", "transaction.py")
ARTIFACTS = _module("trial_artifacts", "artifacts.py")
PREPARATION = _module("trial_preparation", "preparation.py")
HOST = _module("trial_observation", "host_observation.py")
WORKFLOW = _module("trial_workflow", "workflow.py")
RETIREMENT = _module("trial_retirement", "slot_retirement.py")
STATE = Path("/var/lib/omarchy/t2-hibernate-trial")
# Each requalified generation gets its own one-use state root beside the original one. The original root, its
# consumed guard and its ledger are never read for, moved to or reset for a generation; the physical-cycle lock
# stays the single global lock in STATE. A generation root is named by the first 12 hex of its manifest digest.
GENERATIONS = STATE / "generations"
GENERATION = re.compile(r"[0-9a-f]{12}\Z")
CONFIG_SCHEMA = "omarchy-t2-explicit-trial-config-v1"
REPAIR_SCHEMA = "omarchy-t2-known-constructor-repair-v1"
REPAIR_BOOT = "b795a460-bf57-4ff6-84b7-4ebc415a9350"
REPAIR_CYCLE = "d8923d12-7794-483f-8746-91face7e2ab9"
REPAIR_VECTOR = "8946b182fa68d358ce5efc50091c3f17189e276ef847bab054f1d0278241a67e"
REPAIR_GUARD_SHA = "fb529b27e9c8507d05270c4b0414c8bd4cbcdbaa42676de4a24370ac502cf2a4"
REPAIR_CYCLE_SHA = "3b6f001a1d2269b1b285553e6a7cc4e47c3b13db04e9f4fa924d1c9bdddbaf37"
REPAIR_UNIT = "codex-mba-product-trial-d596155a.service"
REPAIR_INVOCATION = "4a1e4bdecb2443f6af8b619f628fc752"
REPAIR_FAILURE_SHA = "ec77d4e23b09c8c548de8124784a58f1249b9db102be306d0e525a80de22e5a7"
REPAIR_SYSTEMD_SHA = "5a715459c620e7795d53b5c2ad57b96ef64690e864f1fffbda7bb81fa3dfc243"


def verify_deployment(root, config, report):
  # Historical trial entry remains strict stock-default verification.
  return _verify_deployment(root, config, report)


def _verify_deployment(root, config, report, *, source_default=False):
  """Read-only existing pair verification; staging state confers no authority."""
  pair = ARTIFACTS._module("trial_staged_pair", ARTIFACTS.HERE.parent / "experiments/stage-hibernation-uki-pair.py")
  def blake2(path):
    digest = hashlib.blake2b()
    for chunk in ARTIFACTS._chunks(path): digest.update(chunk)
    return digest.hexdigest()
  # Existing boot verifier uses unbounded image reads. Preserve its exact
  # checks while supplying streaming hash primitives in this private module.
  pair.SINGLE.digest = ARTIFACTS._file_digest
  pair.SINGLE.blake2 = blake2
  receipt_path = Path(root) / pair.RECEIPT
  raw = HOST._raw(receipt_path, private=True)
  HOST.CT.exact(HOST._digest(raw), config["staged_receipt_sha256"], "Audited staged receipt bytes")
  receipt = json.loads(raw, object_pairs_hook=TX.no_duplicates)
  HOST.CT.exact(receipt["kernel_policy"], "production-linux-unchanged", "Staged production kernel policy")
  for role in ("source", "restore"):
    HOST.CT.exact(receipt["images"][role]["sha256"], report["manifest"][role + "_sha256"], "Staged " + role + " pin")
    HOST.CT.exact(receipt["images"][role]["provenance_sha256"], report["audited_details"]["provenance_sha256"][role], "Staged " + role + " provenance")
  HOST.CT.exact(receipt["production_uki_sha256"], report["audited_details"]["production_uki_sha256"], "Staged production pin")
  pair.verify_staged(Path(root), receipt, source_default=source_default)
  # The older staging-only production helper requires a stock-selected boot
  # and absent one-shot. Those gates are incompatible with source preparation.
  production = Path(root) / "boot/EFI/Linux" / pair.SINGLE.PRODUCTION_IMAGE
  expected = "path: boot():/EFI/Linux/" + pair.SINGLE.PRODUCTION_IMAGE + "#" + blake2(production)
  text = HOST._raw(Path(root) / pair.SINGLE.LIMINE).decode()
  if text.count(expected) != 1:
    raise ValueError("Production Limine mapping is stale or ambiguous")
  pair.advertised_entries(Path(root), receipt)


def verify_readiness(root, config, authorization, report):
  """Reject known-unready first-trial source state before consuming authority."""
  root = Path(root)
  mounts = [line.split() for line in HOST._raw(root / "proc/self/mounts").decode().splitlines() if len(line.split()) >= 4 and line.split()[1] == "/"]
  if len(mounts) != 1 or mounts[0][0] != "/dev/mapper/root" or mounts[0][2] != "btrfs" or "subvol=/@" not in mounts[0][3].split(","):
    raise ValueError("Trial requires mounted primary encrypted Btrfs root subvolume @")
  HOST.CT.exact(HOST._raw(root / "proc/sys/kernel/random/boot_id").decode().strip(), authorization["original_boot_id"], "Ready original boot")
  source = "MBA-T2-hibernation-source-" + report["manifest"]["source_sha256"][:16]
  selected = root / HOST.EFI / ("LoaderEntrySelected-" + HOST.LOADER_GUID)
  HOST.CT.exact(HOST._raw(selected), b"\x06\0\0\0" + (source + "\0").encode("utf-16-le"), "Ready ordinary source selection")
  for name in (HOST.CT.SOURCE_VARIABLE, HOST.CT.RESTORE_VARIABLE, "LoaderEntryOneShot-" + HOST.LOADER_GUID, "LoaderEntryDefault-" + HOST.LOADER_GUID):
    path = root / HOST.EFI / name
    if path.exists() or path.is_symlink():
      raise ValueError("Historical or foreign EFI evidence/override occupies trial slot")
  module = root / "sys/module" / HOST.MARKER
  loaded = HOST._raw(root / "proc/modules").decode().splitlines()
  if module.exists() or module.is_symlink() or any(line.split() and line.split()[0] == HOST.MARKER for line in loaded):
    raise ValueError("Source marker already loaded")
  supplies = root / "sys/class/power_supply"
  if not supplies.is_dir() or not any(HOST._raw(path / "type").decode().strip() == "Mains" and HOST._raw(path / "online").decode().strip() == "1" for path in supplies.iterdir()):
    raise ValueError("Live AC power required for explicit trial")
  _platform_readiness(root, report)


def _platform_readiness(root, report):
  backend = _module("trial_readonly_platform", "host_backend.py")
  backend.verify_readiness(root, report)


def validate(config, authorization, report, boot_id):
  keys = {"schema", "source_directory", "restore_directory", "production_uki", "source_tree", "marker_file",
          "marker_pin", "manifest", "audited_details_sha256", "staged_receipt_sha256", "retire_slots"}
  if type(config) is not dict or set(config) != keys or config["schema"] != CONFIG_SCHEMA or type(config["retire_slots"]) is not bool:
    raise ValueError("Explicit audited trial config fields differ")
  for key in ("source_directory", "restore_directory", "production_uki", "source_tree", "marker_file"):
    if type(config[key]) is not str or not Path(config[key]).is_absolute():
      raise ValueError("Absolute audited artifact paths required")
  authority = TX.trial_value(authorization, report["manifest"])
  TX.hash_value(config["staged_receipt_sha256"])
  HOST.CT.exact(config["manifest"], report["manifest"], "Actual audited trial manifest")
  HOST.CT.exact(report["audited_details_sha256"], TX.digest(report["audited_details"]), "Actual audit details digest")
  for value in (config["audited_details_sha256"], authority["audited_details_sha256"]):
    HOST.CT.exact(value, report["audited_details_sha256"], "Authorized exact artifact details")
  HOST.CT.exact(config["marker_pin"], authority["marker_pin"], "Authorized exact source marker")
  backend = _module("trial_static_backend", "host_backend.py")
  backend.validate_static_inputs(report, report["manifest"], config["marker_file"], config["marker_pin"])
  HOST.CT.exact(boot_id, authority["original_boot_id"], "Current authorized original boot")
  HOST.CT.exact(ARTIFACTS._file_digest(config["marker_file"]), authority["marker_pin"]["sha256"], "Actual external marker bytes")
  return authority


def execute(config, authorization, report, *, ledger, guard_directory, archive_directory, root, backend_factory, sleeper,
            deployment_check=verify_deployment):
  """Run explicit supplied adapters; no live paths or authority are inferred."""
  boot_id = HOST._raw(Path(root) / "proc/sys/kernel/random/boot_id").decode().strip()
  authority = validate(config, authorization, report, boot_id)
  deployment_check(root, config, report)
  verify_readiness(root, config, authority, report)
  ledger.configure(report["manifest"])
  ledger.authorize_trial(authority, guard_directory)
  cycle = ledger.begin(boot_id)
  return _run_reserved(config, authority, report, cycle, ledger=ledger, archive_directory=archive_directory,
                       root=root, backend_factory=backend_factory, sleeper=sleeper, deployment_check=deployment_check)


def _run_reserved(config, authority, report, cycle, *, ledger, archive_directory, root, backend_factory, sleeper,
                  deployment_check=verify_deployment):
  """Internal execution body; this does not grant reservation or retry authority."""
  TX.cycle_value(cycle)
  HOST.CT.exact(cycle["state"], "reserved", "Reserved execution state")
  HOST.CT.exact(cycle["original_boot_id"], authority["original_boot_id"], "Reserved execution boot")
  HOST.CT.exact(cycle["manifest"], report["manifest"], "Reserved execution artifacts")
  HOST.CT.exact(cycle["qualification_sha256"], TX.digest(authority), "Reserved execution authority")
  ledger.compare_and_run(cycle, lambda advance: HOST.CT.exact(advance.check_current(), cycle, "Current reserved execution"))
  backend = backend_factory(root, report, cycle, config["marker_file"], config["marker_pin"])
  preparation = PREPARATION.Preparation(ledger, cycle, backend, config["marker_file"], config["marker_pin"], sleeper=sleeper)
  prepared = preparation.prepare()
  try:
    sampler = HOST.Sampler(root, report, prepared["cycle"], authority, config["source_directory"], config["source_tree"],
                           config["marker_file"], config["marker_pin"], prepared["guard_file"], prepared["attempt_file"], query=backend.query)
    before = sampler.before(prepared["receipt"])
    collector = WORKFLOW.CONTINUITY.Collector(prepared["cycle"], authority, before["source_runtime"], before["baseline_pm"],
                                             prepared["guard_file"].read_bytes(), prepared["attempt_file"].read_bytes())
    backend_writer = backend.power_writer(ledger, prepared["cycle"], prepared["receipt"])
    class DeploymentPower:
      def bind_locked(self, advance):
        if hasattr(backend_writer, "bind_locked"):
          backend_writer.bind_locked(advance)
      def __call__(self, path, value):
        deployment_check(root, config, report)
        return backend_writer(path, value)
    writer = DeploymentPower()
  except BaseException as error:
    errors = preparation.cleanup()
    ledger.advance(cycle["cycle_id"], "failed", TX.digest({"phase": "trial-before-write", "error": type(error).__name__, "cleanup": errors}))
    raise
  result = WORKFLOW.run(ledger, collector, archive_directory, power_write=writer, capture=sampler.capture,
                        cleanup=preparation.cleanup, health=sampler.health)
  if config["retire_slots"]:
    read_slot, delete = backend.retirement_callbacks(ledger, result["cycle"], archive_directory)
    result["retirement"] = RETIREMENT.retire(ledger, result["cycle"], archive_directory, read_slot=read_slot,
      compare_delete_slot=delete, health=backend.retirement_health(sampler, collector.binding))
  result["classification"] = "one-use-product-trial-not-usable-qualification"
  return result


def _repair_raw(directory, name):
  path = Path(directory) / name
  if any(item.is_symlink() for item in (path, *path.parents)):
    raise ValueError("Symlinked constructor repair evidence")
  return HOST._raw(path, private=True)


def repair_constructor(config, authorization, report, *, ledger, guard_directory, archive_directory, root,
                       repair_directory, backend_factory, sleeper, deployment_check=verify_deployment):
  """Continue only the pinned constructor-only failure, once, on its SAME cycle.

  The external root-private repair receipt is separately reviewed permission,
  not product qualification. Missing/changed state or any started repair blocks
  continuation. No consumed guard, failed unit, ledger or allocation is reset.
  The live caller holds the global physical lock; the short ledger scope ends
  before Preparation takes that same lock independently.
  """
  root, repair_directory = Path(root), Path(repair_directory)
  if root == Path("/"):
    for actual, expected in ((repair_directory, STATE), (ledger.directory, STATE / "ledger"),
                             (Path(guard_directory), STATE / "guards"), (Path(archive_directory), STATE / "archives")):
      HOST.CT.exact(actual, expected, "Fixed live constructor repair paths")
  info = repair_directory.lstat()
  if repair_directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
    raise ValueError("Private constructor repair directory required")
  boot_id = HOST._raw(root / "proc/sys/kernel/random/boot_id").decode().strip()
  HOST.CT.exact(boot_id, REPAIR_BOOT, "Known constructor failure boot")
  authority = validate(config, authorization, report, boot_id)
  deployment_check(root, config, report)
  verify_readiness(root, config, authority, report)
  receipt_raw = _repair_raw(repair_directory, "constructor-repair-authorization.json")
  receipt = json.loads(receipt_raw, object_pairs_hook=TX.no_duplicates)
  HOST.CT.fields(receipt, ("schema", "accepted", "boot_id", "cycle_id", "vector", "pins", "implementation_sha256"), "Constructor repair authority")
  for key, expected in (("schema", REPAIR_SCHEMA), ("accepted", True), ("boot_id", REPAIR_BOOT), ("cycle_id", REPAIR_CYCLE), ("vector", REPAIR_VECTOR)):
    HOST.CT.exact(receipt[key], expected, "Known constructor repair authority")
  HOST.CT.fields(receipt["pins"], ("config_sha256", "authorization_sha256", "cycle_sha256", "consumed_guard_sha256", "failure_evidence_sha256"), "Constructor repair pins")
  for pin in receipt["pins"].values(): TX.hash_value(pin)
  for name, expected in (("config.json", config), ("authorization.json", authorization)):
    raw = _repair_raw(repair_directory, name)
    HOST.CT.exact(json.loads(raw, object_pairs_hook=TX.no_duplicates), expected, "Retained original constructor inputs")
    HOST.CT.exact(HOST._digest(raw), receipt["pins"][name.removesuffix(".json") + "_sha256"], "Retained input raw hash")
  failure_raw = _repair_raw(repair_directory, "constructor-only-failure.json")
  HOST.CT.exact(HOST._digest(failure_raw), REPAIR_FAILURE_SHA, "Known constructor failure evidence hash")
  HOST.CT.exact(REPAIR_FAILURE_SHA, receipt["pins"]["failure_evidence_sha256"], "Repair failure pin")
  failure = json.loads(failure_raw, object_pairs_hook=TX.no_duplicates)
  HOST.CT.exact(failure, {"schema": "omarchy-t2-constructor-only-failure-v1", "phase": "backend-constructor",
    "error": "Invalid backend marker srcversion", "prepared": False, "power_write": False, "boot_id": REPAIR_BOOT,
    "cycle_id": REPAIR_CYCLE, "vector": REPAIR_VECTOR, "systemd_failure_archive_sha256": REPAIR_SYSTEMD_SHA}, "Known constructor-only failure")
  systemd_raw = _repair_raw(repair_directory, "constructor-systemd-failure.json")
  HOST.CT.exact(HOST._digest(systemd_raw), REPAIR_SYSTEMD_SHA, "Known archived failed unit hash")
  systemd = json.loads(systemd_raw, object_pairs_hook=TX.no_duplicates)
  HOST.CT.fields(systemd, ("boot_id", "unit", "invocation_id", "show", "journal"), "Archived constructor unit")
  for key, expected in (("boot_id", REPAIR_BOOT), ("unit", REPAIR_UNIT), ("invocation_id", REPAIR_INVOCATION)):
    HOST.CT.exact(systemd[key], expected, "Known archived failed invocation")
  if type(systemd["show"]) is not str or "Result=exit-code" not in systemd["show"] or "ExecMainStatus=1" not in systemd["show"] or type(systemd["journal"]) is not str or "Invalid backend marker srcversion" not in systemd["journal"]:
    raise ValueError("Missing exact constructor failure trace")
  HOST.CT.fields(receipt["implementation_sha256"], ("trial.py", "host_backend.py", "preparation.py", "continuity.py"), "Reviewed constructor repair implementation")
  for name, pin in receipt["implementation_sha256"].items():
    HOST.CT.exact(ARTIFACTS._file_digest(Path(__file__).with_name(name)), TX.hash_value(pin), "Reviewed exact repair code")
  cycle_raw = _repair_raw(ledger.directory, "cycle-" + REPAIR_CYCLE + ".json")
  HOST.CT.exact(HOST._digest(cycle_raw), REPAIR_CYCLE_SHA, "Known untouched reserved cycle bytes")
  HOST.CT.exact(REPAIR_CYCLE_SHA, receipt["pins"]["cycle_sha256"], "Repair original cycle pin")
  cycle = TX.cycle_value(json.loads(cycle_raw, object_pairs_hook=TX.no_duplicates))
  for key, expected in (("state", "reserved"), ("original_boot_id", REPAIR_BOOT), ("cycle_id", REPAIR_CYCLE), ("vector", REPAIR_VECTOR)):
    HOST.CT.exact(cycle[key], expected, "Known reserved constructor cycle")
  guard_raw = _repair_raw(guard_directory, "trial-consumed.json")
  HOST.CT.exact(HOST._digest(guard_raw), REPAIR_GUARD_SHA, "Known consumed trial guard")
  HOST.CT.exact(REPAIR_GUARD_SHA, receipt["pins"]["consumed_guard_sha256"], "Repair original guard pin")
  HOST.CT.exact(json.loads(guard_raw, object_pairs_hook=TX.no_duplicates),
                {"protocol": TX.TRIAL_PROTOCOL, "authorization_sha256": TX.digest(authority), "cycle": cycle}, "Original guard cycle authority")
  intent_name = "constructor-repair-intent.json"
  intent = {"schema": REPAIR_SCHEMA, "repair_authorization_sha256": HOST._digest(receipt_raw), "cycle": cycle,
            "constructor_only_failure_sha256": REPAIR_FAILURE_SHA, "implementation_sha256": receipt["implementation_sha256"]}
  def consume(advance):
    HOST.CT.exact(advance.check_current(), cycle, "Locked original constructor cycle")
    HOST.CT.exact({item.name for item in ledger.directory.iterdir()}, {"lock", "state.json", "allocation-head.json",
                  "allocation-" + REPAIR_CYCLE + ".json", "cycle-" + REPAIR_CYCLE + ".json"}, "Constructor-only ledger file set")
    HOST.CT.exact({item.name for item in Path(guard_directory).iterdir()}, {"lock", "trial-consumed.json"}, "Constructor-only guard file set")
    if any(Path(archive_directory).iterdir()): raise ValueError("Constructor failure already has archive state")
    if (repair_directory / intent_name).exists() or (repair_directory / intent_name).is_symlink():
      raise ValueError("Constructor repair permanently consumed; no retry")
    HOST.CT.exact(_repair_raw(ledger.directory, "cycle-" + REPAIR_CYCLE + ".json"), cycle_raw, "Locked raw reserved cycle")
    HOST.CT.exact(_repair_raw(guard_directory, "trial-consumed.json"), guard_raw, "Locked raw consumed guard")
    # Dedicated private-directory writer supplies exclusive publication and
    # file+directory fsync; no replacement or deletion of the original guard.
    repair = TX.Ledger(repair_directory)
    repair._write(intent_name, intent, exclusive=True)
  ledger.compare_and_run(cycle, consume)
  return _run_reserved(config, authority, report, cycle, ledger=ledger, archive_directory=archive_directory,
                       root=root, backend_factory=backend_factory, sleeper=sleeper, deployment_check=deployment_check)


def _private_json(path):
  path = Path(path)
  if any(parent.is_symlink() for parent in (path, *path.parents)):
    raise ValueError("Symlinked live trial configuration")
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  with os.fdopen(fd, "rb") as stream:
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 2 * 1024 * 1024:
      raise ValueError("Live trial configuration must be root-owned private bounded JSON")
    return json.loads(stream.read(2 * 1024 * 1024 + 1), object_pairs_hook=TX.no_duplicates)


@contextlib.contextmanager
def _global_lock():
  """Fixed pre-provisioned private lock, held across the entire physical cycle."""
  path = STATE / "physical-cycle.lock"
  if any(parent.is_symlink() for parent in (path, *path.parents)):
    raise ValueError("Symlinked global trial lock")
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
  try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
      raise ValueError("Fixed root-private global cycle lock required")
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    yield
  finally:
    os.close(fd)


def _refuse_original_manifest(manifest):
  """A generation root may never re-run the original one-use trial, under any name.

  The original root's manifest is known from its consumed guard record and its config; both are read fail-closed.
  """
  known = set()
  guard = STATE / "guards/trial-consumed.json"
  if guard.exists() or guard.is_symlink():
    record = _private_json(guard)
    cycle = record.get("cycle") if type(record) is dict else None
    if type(cycle) is not dict or type(cycle.get("manifest")) is not dict: raise ValueError("Original consumed guard is unreadable; no generation trial")
    known.add(TX.digest(cycle["manifest"]))
  config = STATE / "config.json"
  if config.exists() or config.is_symlink():
    value = _private_json(config)
    if type(value) is dict and type(value.get("manifest")) is dict: known.add(TX.digest(value["manifest"]))
  if TX.digest(manifest) in known: raise ValueError("The original one-use trial manifest cannot be re-run through a generation root")


def generation_root(manifest_or_id):
  """Fixed one-use state root of one requalified generation, from its manifest (or its 12-hex digest prefix)."""
  identity = manifest_or_id if type(manifest_or_id) is str else TX.digest(TX.manifest_value(manifest_or_id))[:12]
  if type(identity) is not str or not GENERATION.fullmatch(identity): raise ValueError("Generation is 12 lowercase hex digits of the manifest digest")
  return GENERATIONS / identity


def _private_directory(directory):
  info = directory.lstat()
  if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
    raise ValueError("Fixed existing root-private trial state directories required")


def main(argv=None):
  parser = argparse.ArgumentParser(description="Explicit one-use T2 trial; no usable qualification or stock hibernate")
  parser.add_argument("action", nargs="?", choices=("inspect", "check", "execute", "repair-constructor"), default="inspect")
  parser.add_argument("--generation", metavar="MANIFEST12", help="use the one-use state root of a requalified generation (12 hex of its manifest digest) instead of the original root")
  args = parser.parse_args(argv)
  if args.generation is not None and (not GENERATION.fullmatch(args.generation) or args.action == "repair-constructor"):
    parser.error("--generation takes 12 lowercase hex digits and never applies to the historical constructor repair")
  if args.action in ("execute", "repair-constructor") and os.geteuid() != 0:
    parser.error("Explicit root invocation required; use sudo. No automatic escalation is performed.")
  with _global_lock():
    if args.generation is None: return _dispatch(args.action)  # the original root: exactly the historical call
    return _dispatch(args.action, generation=args.generation)


def _dispatch(action, generation=None):
  state = STATE if generation is None else generation_root(generation)
  if generation is not None:
    for directory in (GENERATIONS, state): _private_directory(directory)
  config = _private_json(state / "config.json")
  authorization = _private_json(state / "authorization.json")
  report = ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  if generation is not None:
    HOST.CT.exact(TX.digest(report["manifest"])[:12], generation, "Generation state root binds the audited manifest")
    _refuse_original_manifest(report["manifest"])
  validate(config, authorization, report, HOST._raw(Path("/proc/sys/kernel/random/boot_id")).decode().strip())
  verify_deployment(Path("/"), config, report)
  verify_readiness(Path("/"), config, authorization, report)
  for directory in (state, state / "guards", state / "ledger", state / "archives"): _private_directory(directory)
  guard = state / "guards/trial-consumed.json"
  if action == "repair-constructor":
    backend = _module("trial_live_backend", "host_backend.py")
    result = repair_constructor(config, authorization, report, ledger=TX.Ledger(state / "ledger"), guard_directory=state / "guards",
                                archive_directory=state / "archives", root=Path("/"), repair_directory=state,
                                backend_factory=backend.HostBackend, sleeper=time.sleep)
    print(json.dumps({"classification": result["classification"], "cycle_id": result["cycle"]["cycle_id"], "state": result["cycle"]["state"]}))
    return 0
  if guard.exists() or guard.is_symlink():
    raise ValueError("One-use trial permanently consumed; no retry or stock fallback")
  if action != "execute":
    print(json.dumps({"classification": "audited-one-use-trial-not-qualified", "execute": False, "manifest_sha256": TX.digest(report["manifest"])}))
    return 0
  backend = _module("trial_live_backend", "host_backend.py")
  result = execute(config, authorization, report, ledger=TX.Ledger(state / "ledger"), guard_directory=state / "guards",
                   archive_directory=state / "archives", root=Path("/"), backend_factory=backend.HostBackend, sleeper=time.sleep)
  print(json.dumps({"classification": result["classification"], "cycle_id": result["cycle"]["cycle_id"], "state": result["cycle"]["state"]}))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
