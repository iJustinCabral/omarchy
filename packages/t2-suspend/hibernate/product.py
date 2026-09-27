"""Qualified routine dispatcher; not qualification issuance or live provisioning.

The fixed live state is separate from the immutable one-use trial. A truthful,
externally issued product receipt is mandatory. The shared physical lock and
private ledger serialize each fresh cycle. Failed, ambiguous or unreconciled
cycles never reset automatically. Import/check performs no preparation or power
operation. Synthetic roots require explicit backends; the CLI has no alternate
root, force, trial-promotion or recovery options.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import time


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


TRIAL = _module("product_shared_lifecycle", "trial.py")
TX, HOST, ARTIFACTS = TRIAL.TX, TRIAL.HOST, TRIAL.ARTIFACTS
PREPARATION, WORKFLOW, RETIREMENT = TRIAL.PREPARATION, TRIAL.WORKFLOW, TRIAL.RETIREMENT
BACKEND = _module("product_fixed_backend", "host_backend.py")
SECURE_SESSION = _module("product_secure_session", "secure_session.py")
DESKTOP_SLEEP = _module("product_desktop_sleep", "desktop_sleep.py")
BOOT_POLICY = _module("product_boot_policy", "boot_policy.py")
UPDATE_GUARD = _module("product_update_guard", "update_guard.py")
STATE = Path("/var/lib/omarchy/t2-hibernate-product")
CONFIG_SCHEMA = "omarchy-t2-qualified-product-config-v1"


def verify_deployment(root, config, report):
  """Routine-only approved default overlay; all historical checks remain."""
  root = Path(root)
  for name in ("source-default-activation.pending", "source-default-deactivation.pending"):
    path = root / BOOT_POLICY.STATE / name
    UPDATE_GUARD._ancestors(root, path, 0 if root == Path("/") else os.geteuid())
    try: path.lstat()
    except FileNotFoundError: continue
    raise ValueError("Incomplete source-default transition blocks routine hibernation")
  source_default = BOOT_POLICY.verify(root, config["staged_receipt_sha256"])
  return TRIAL._verify_deployment(root, config, report, source_default=source_default)


def validate(config, qualification, report):
  keys = {"schema", "source_directory", "restore_directory", "production_uki", "source_tree", "marker_file",
          "marker_pin", "manifest", "audited_details_sha256", "staged_receipt_sha256"}
  HOST.CT.fields(config, keys, "Qualified product configuration")
  HOST.CT.exact(config["schema"], CONFIG_SCHEMA, "Qualified product configuration protocol")
  for key in ("source_directory", "restore_directory", "production_uki", "source_tree", "marker_file"):
    if type(config[key]) is not str or not Path(config[key]).is_absolute(): raise ValueError("Absolute product artifact paths required")
  receipt = TX.receipt_value(qualification, report["manifest"])
  HOST.CT.exact(config["manifest"], report["manifest"], "Actual qualified product artifact pins")
  HOST.CT.exact(config["audited_details_sha256"], report["audited_details_sha256"], "Actual qualified artifact details")
  TX.hash_value(config["staged_receipt_sha256"])
  BACKEND.validate_static_inputs(report, report["manifest"], config["marker_file"], config["marker_pin"])
  HOST.CT.exact(ARTIFACTS._file_digest(config["marker_file"]), config["marker_pin"]["sha256"], "Actual qualified external marker bytes")
  return receipt


def _head(ledger):
  """Read the real terminal allocation, never fabricate a future cycle."""
  state = ledger._state() if (ledger.directory / "state.json").exists() else None
  if state is not None and "trial_guard_directory" in state: raise ValueError("Trial ledger cannot become routine product authority")
  if state is not None and state["blocked"]: raise ValueError("Product pair remains failure-blocked")
  if any(ledger.directory.glob("slot-retirement-*-unresolved.json")): raise ValueError("Unresolved retirement blocks routine invocation")
  cycles = ledger._cycles()
  if any(cycle["state"] != "reconciled" for cycle in cycles): raise ValueError("Product cycle remains active, failed or ambiguous")
  ledger._retirement_completions(cycles)
  return state, ledger._allocation_head(cycles)


def check(config, qualification, report, *, ledger, archive_directory, root, query=None,
          deployment_check=verify_deployment):
  """Read-only admission, including the actual immediately prior return."""
  root = Path(root)
  if root == Path("/") and (query is not None or deployment_check is not verify_deployment):
    raise ValueError("No injected live product admission")
  receipt = validate(config, qualification, report)
  deployment_check(root, config, report)
  return _admission_state(config, receipt, report, ledger=ledger, archive_directory=archive_directory, root=root, query=query)


def _admission_state(config, receipt, report, *, ledger, archive_directory, root, query=None):
  """Shared read-only host/ledger checks; callers separately verify deployment."""
  BACKEND.verify_readiness(root, report, command_runner=query)
  boot = TX.uuid_value(HOST._raw(root / "proc/sys/kernel/random/boot_id").decode().strip())
  selected_raw = HOST._raw(root / HOST.EFI / ("LoaderEntrySelected-" + HOST.LOADER_GUID))
  entries = {role: b"\x06\0\0\0" + ("MBA-T2-hibernation-" + role + "-" + report["manifest"][role + "_sha256"][:16] + "\0").encode("utf-16-le") for role in ("source", "restore")}
  for name in ("LoaderEntryOneShot", "LoaderEntryDefault", HOST.CT.SOURCE_VARIABLE, HOST.CT.RESTORE_VARIABLE):
    fixed = name + "-" + HOST.LOADER_GUID if name.startswith("Loader") else name
    path = root / HOST.EFI / fixed
    if path.exists() or path.is_symlink(): raise ValueError("Product EFI override or unresolved reusable stage slot")
  loaded = {line.split()[0] for line in HOST._raw(root / "proc/modules").decode().splitlines() if line.split()}
  loaded |= {item.name for item in (root / "sys/module").iterdir()}
  if any(name.startswith("mba_hibernate_") or "abort" in name.lower() for name in loaded): raise ValueError("Marker, cold or abort module still loaded")
  mounts = [line.split() for line in HOST._raw(root / "proc/self/mounts").decode().splitlines() if len(line.split()) >= 4 and line.split()[1] == "/"]
  if len(mounts) != 1 or mounts[0][:3] != ["/dev/mapper/root", "/", "btrfs"] or "subvol=/@" not in mounts[0][3].split(","):
    raise ValueError("Qualified product requires primary encrypted root")
  supplies = root / "sys/class/power_supply"
  if not any(HOST._raw(item / "type").strip() == b"Mains" and HOST._raw(item / "online").strip() == b"1" for item in supplies.iterdir() if (item / "type").is_file() and (item / "online").is_file()):
    raise ValueError("Live AC required")
  with ledger._lock():
    state, previous = _head(ledger)
    if previous is not None:
      RETIREMENT._archived_evidence(archive_directory, previous)
    if selected_raw != entries["source"]:
      HOST.CT.exact(selected_raw, entries["restore"], "Source or exact validated same-session return selection")
      if state is None or previous is None: raise ValueError("First product cycle requires ordinary source selection")
      HOST.CT.exact(state["qualification"], receipt, "Current retained product authority")
      for key, expected in (("original_boot_id", boot), ("manifest", report["manifest"]), ("qualification_sha256", TX.digest(receipt))):
        HOST.CT.exact(previous[key], expected, "Immediate reconciled same-session predecessor")
      ledger._read("slot-retirement-" + previous["cycle_id"] + "-intent.json")
  return {"qualification": receipt, "original_boot_id": boot, "manifest_sha256": TX.digest(report["manifest"]),
          "predecessor_cycle_id": None if previous is None else previous["cycle_id"], "execute": False}


def execute(config, qualification, report, *, ledger, archive_directory, root, backend_factory, sleeper,
            query=None, deployment_check=verify_deployment, desktop=False, secure_gate=None, desktop_window=None):
  """Run one fresh qualified cycle, archive and reconcile, never issue a receipt."""
  root = Path(root)
  if root.resolve() == Path("/") and (secure_gate is not None or desktop_window is not None):
    raise ValueError("No injected live desktop gate or sleep window")
  if not desktop and (secure_gate is not None or desktop_window is not None):
    raise ValueError("Desktop adapters require desktop admission")
  if root == Path("/") and backend_factory is not BACKEND.HostBackend: raise ValueError("Fixed native live product backend required")
  admitted = check(config, qualification, report, ledger=ledger, archive_directory=archive_directory, root=root,
                   query=query, deployment_check=deployment_check)
  if desktop:
    secure_gate = SECURE_SESSION.Gate(root) if secure_gate is None else secure_gate
    desktop_window = DESKTOP_SLEEP.window if desktop_window is None else desktop_window
    session_binding = secure_gate.require_secure()
  receipt = admitted["qualification"]
  ledger.configure(report["manifest"])
  ledger.qualify(receipt)
  cycle = ledger.begin(admitted["original_boot_id"])
  preparation = None
  phase = "backend-constructor"
  try:
    backend = backend_factory(root, report, cycle, config["marker_file"], config["marker_pin"])
    phase = "preparation"
    preparation = PREPARATION.Preparation(ledger, cycle, backend, config["marker_file"], config["marker_pin"],
                                          sleeper=sleeper, predecessor_archive_directory=archive_directory)
    prepared = preparation.prepare()
    phase = "original-source-collector"
    sampler = HOST.Sampler(root, report, prepared["cycle"], receipt, config["source_directory"], config["source_tree"],
                           config["marker_file"], config["marker_pin"], prepared["guard_file"], prepared["attempt_file"], query=backend.query)
    before = sampler.before(prepared["receipt"], predecessor_ledger=ledger, predecessor_archive_directory=archive_directory)
    collector = WORKFLOW.CONTINUITY.Collector(prepared["cycle"], receipt, before["source_runtime"], before["baseline_pm"],
                                             prepared["guard_file"].read_bytes(), prepared["attempt_file"].read_bytes())
    native_writer = backend.power_writer(ledger, prepared["cycle"], prepared["receipt"])
    class DeploymentPower:
      window = None
      def bind_locked(self, advance): native_writer.bind_locked(advance)
      def __call__(self, path, value):
        deployment_check(root, config, report)
        if desktop:
          secure_gate.require_secure(session_binding)
          window = desktop_window(root)
          window.__enter__()
          self.window = window
          # IPC was secure immediately before freezing. Pre-hooks may take
          # time; rebind logind identity here without querying the frozen user.
          secure_gate.require_same_session(session_binding)
        return native_writer(path, value)
      def cleanup(self):
        errors = []
        try:
          if self.window is not None:
            window, self.window = self.window, None
            window.__exit__(None, None, None)
        except BaseException as error:
          errors.append("desktop-sleep-cleanup:" + type(error).__name__)
        finally:
          errors.extend(preparation.cleanup())
        return errors
    writer = DeploymentPower()
  except BaseException as error:
    errors = [] if preparation is None else preparation.cleanup()
    try: ledger.advance(cycle["cycle_id"], "failed", TX.digest({"phase": phase, "error": type(error).__name__, "cleanup": errors}))
    except BaseException as latch: error.add_note("Cycle remains blocked/incomplete: " + type(latch).__name__)
    raise
  result = WORKFLOW.run(ledger, collector, archive_directory, power_write=writer, capture=sampler.capture,
                        cleanup=writer.cleanup, health=sampler.health)
  read_slot, delete = backend.retirement_callbacks(ledger, result["cycle"], archive_directory)
  retired = RETIREMENT.retire(ledger, result["cycle"], archive_directory, read_slot=read_slot, compare_delete_slot=delete,
                            health=backend.retirement_health(sampler, collector.binding))
  return {"cycle": retired["cycle"], "archive_receipt": result["archive_receipt"], "retirement": retired,
          "classification": "qualified-product-cycle-reconciled", "qualification_issued": False}


def main(argv=None):
  parser = argparse.ArgumentParser(description="Externally qualified routine hibernation; no qualification or recovery bypass")
  parser.add_argument("action", nargs="?", choices=("check", "hibernate"), default="check")
  parser.add_argument("--desktop", action="store_true", help="Require the active desktop secure-session gate and sleep compatibility window")
  args = parser.parse_args(argv)
  if args.desktop and args.action != "hibernate": parser.error("Desktop admission requires hibernate")
  if args.action == "hibernate" and os.geteuid() != 0: parser.error("Explicit root invocation required; no automatic escalation")
  # Shared with the one-use dispatcher, not a second independent lock.
  with TRIAL._global_lock():
    for directory in (STATE, STATE / "ledger", STATE / "archives"):
      info = directory.lstat()
      if directory.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Fixed existing root-private product state required")
    config = TRIAL._private_json(STATE / "config.json")
    qualification = TRIAL._private_json(STATE / "qualification.json")
    report = ARTIFACTS.derive_artifacts(config["source_directory"], config["restore_directory"], config["production_uki"])
    ledger = TX.Ledger(STATE / "ledger")
    arguments = {"ledger": ledger, "archive_directory": STATE / "archives", "root": Path("/")}
    if args.action == "hibernate":
      result = execute(config, qualification, report, **arguments, backend_factory=BACKEND.HostBackend, sleeper=time.sleep,
                       desktop=args.desktop)
      output = {"classification": result["classification"], "cycle_id": result["cycle"]["cycle_id"], "state": result["cycle"]["state"]}
    else: output = check(config, qualification, report, **arguments)
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__": raise SystemExit(main())
