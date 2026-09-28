"""One fixture-only maintenance owner lifetime, NOT enabled native admission.

Joins real fresh-client descriptor handoff, fixed held user launches and
concurrent hook servicing to the existing durable maintenance/physical scope.
Exclusion/precheck callbacks are trusted disposable fixtures. They cannot be
used on '/' or an alias; they are not real inhibitor/session/sudo proof.

The native owner/public client/guard remain unavailable. Direct-child cleanup
does not drain descendants; the transition's fixture exception exit cannot
retain physical exclusion on unconfirmed veto durability. Native integration
must resolve both before any package admission. No automatic replay, generation
reactivation, bootability or qualification claim follows from phase completion.
"""
import importlib.util
import math
import os
from pathlib import Path


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


M = _module("coordinator_maintenance", "package_maintenance.py")
H = _module("coordinator_handoff", "maintenance_handoff.py")
L = _module("coordinator_launcher", "maintenance_launcher.py")
B = _module("coordinator_broker", "maintenance_broker.py")
HOOK_SOCKET = "package-maintenance-hook.sock"


def _inside(root, path):
  try: return Path(path).resolve().relative_to(root)
  except ValueError: raise ValueError("Fixture controls must remain inside disposable root") from None


def coordinate(root, stream, *, sender_identity, runtime_directory, user_environment,
               precheck, exclusion, hook_identity, intermediary_identity,
               phase_timeout=10.0, handoff_timeout=1.0):
  """One fresh handoff/owner scope; caller owns stream, owner owns receipt/children.

  exclusion() is a fixture context yielding a raising power_guard. The supplied
  account environment is snapshotted, passwd-bound and tied to the actual peer
  UID, never an asserted target UID. Returncodes flow to existing exclusive
  phase evidence; a signal/exception is refusal, not a successful phase result.
  A failed post-return gate records failure, not its in-memory child status;
  these diagnostics do not promise an exit record for every interrupted phase.
  Source fixture timeouts are not a production package-update timeout policy.
  """
  root = M._fixture(root)  # BEFORE a handshake, exclusion or caller callback
  if not callable(precheck) or not callable(exclusion) or type(user_environment) is not dict:
    raise ValueError("Explicit fixture exclusion/precheck and user environment required")
  if type(phase_timeout) not in (int, float) or not math.isfinite(phase_timeout) or not 0 < phase_timeout <= 30:
    raise ValueError("Explicit bounded fixture phase deadline required")
  H.P._timeout(handoff_timeout)
  environment = dict(user_environment)
  hook, intermediary = dict(hook_identity), dict(intermediary_identity)
  B._identity(hook)
  if set(intermediary) != {"uid", "exe"} or type(intermediary["uid"]) is not int or intermediary["uid"] < 0 or type(intermediary["exe"]) is not str:
    raise ValueError("Exact fixture intermediary UID/executable required")
  _inside(root, runtime_directory)
  if "OMARCHY_PATH" not in environment: raise ValueError("Explicit fixture Omarchy path required")
  _inside(root, environment["OMARCHY_PATH"])
  with exclusion() as power_guard:
    if not callable(power_guard): raise ValueError("Scoped raising fixture power guard required")
    power_guard()
    with H.receive_lock(stream, sender_identity=sender_identity, runtime_directory=runtime_directory,
                        timeout=handoff_timeout) as receipt:
      if environment.get("XDG_RUNTIME_DIR") != str(receipt.directory):
        raise ValueError("User runtime context differs from authenticated lock receipt")
      directory, _ = L._context(receipt.peer.uid, environment)
      _inside(root, directory / "bin")
      for command in L.PHASES.values(): _inside(root, directory / "bin" / command[0])
      current = B.P._identity(os.getpid())
      owner = {"uid": current["uids"][1], "exe": current["exe"], "argv": list(current["argv"])}

      def watch():
        receipt.check()
        power_guard()
        receipt.check()

      def checked_precheck(target, action, stage):
        watch()
        precheck(target, action, stage)
        watch()

      def phase(name, session):
        def gate():
          watch()
          result = M.check_maintenance(root, session)
          watch()
          return result
        gate()  # expensive admission BEFORE the five-second held bootstrap
        _inside(root, directory / "bin" / L.PHASES[name][0])
        held = L.launch(name, uid=receipt.peer.uid, environment=environment, update_lock_fd=receipt.fd)
        try:
          code = B.run_phase(root, root / HOOK_SOCKET, launch=lambda _: held.process,
            phase_identity=held.identity, release=held.release, owner_identity=owner,
            hook_identity=hook, intermediary_identity=intermediary, gate=gate,
            watch=watch, cancel_fd=receipt.peer.fd, timeout=phase_timeout)
          gate()  # includes last phase, INSIDE durable maintenance/physical scope
          return code
        finally:
          # Broker owns the only reaper until it returns/raises. This finalizer
          # closes the launcher's private descriptors even on bad-pin refusal.
          held.abort()

      watch()
      result = M.coordinate(root, precheck=checked_precheck, run_phase=phase, guard=watch)
      watch()
      return result
