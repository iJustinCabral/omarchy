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
CONFIG_SCHEMA = "omarchy-t2-explicit-trial-config-v1"


def verify_deployment(root, config, report):
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
  pair.verify_staged(Path(root), receipt)
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


def main(argv=None):
  parser = argparse.ArgumentParser(description="Explicit one-use T2 trial; no usable qualification or stock hibernate")
  parser.add_argument("action", nargs="?", choices=("inspect", "check", "execute"), default="inspect")
  args = parser.parse_args(argv)
  if args.action == "execute" and os.geteuid() != 0:
    parser.error("Explicit root invocation required; use sudo. No automatic escalation is performed.")
  with _global_lock():
    return _dispatch(args.action)


def _dispatch(action):
  config = _private_json(STATE / "config.json")
  authorization = _private_json(STATE / "authorization.json")
  report = ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
  validate(config, authorization, report, HOST._raw(Path("/proc/sys/kernel/random/boot_id")).decode().strip())
  verify_deployment(Path("/"), config, report)
  verify_readiness(Path("/"), config, authorization, report)
  for directory in (STATE, STATE / "guards", STATE / "ledger", STATE / "archives"):
    info = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
      raise ValueError("Fixed existing root-private trial state directories required")
  guard = STATE / "guards/trial-consumed.json"
  if guard.exists() or guard.is_symlink():
    raise ValueError("One-use trial permanently consumed; no retry or stock fallback")
  if action != "execute":
    print(json.dumps({"classification": "audited-one-use-trial-not-qualified", "execute": False, "manifest_sha256": TX.digest(report["manifest"])}))
    return 0
  backend = _module("trial_live_backend", "host_backend.py")
  result = execute(config, authorization, report, ledger=TX.Ledger(STATE / "ledger"), guard_directory=STATE / "guards",
                   archive_directory=STATE / "archives", root=Path("/"), backend_factory=backend.HostBackend, sleeper=time.sleep)
  print(json.dumps({"classification": result["classification"], "cycle_id": result["cycle"]["cycle_id"], "state": result["cycle"]["state"]}))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
