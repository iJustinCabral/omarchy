"""One fixture-only maintenance owner lifetime, NOT enabled native admission.

Joins real fresh-client descriptor handoff, fixed held user launches and
concurrent hook servicing to the existing durable maintenance/physical scope.
Exclusion/precheck callbacks are trusted disposable fixtures. They cannot be
used on '/' or an alias; they are not real inhibitor/session/sudo proof.

The native owner/public client/guard remain unavailable. Optional retained
fixture recovery joins owned scope settlement and exact durable veto repair
inside both exclusions; omitted seams preserve old fixture behavior, NOT native
retention. Real manager scopes/authentication are not simulated into permission.
No automatic replay, generation
reactivation, bootability or qualification claim follows from phase completion.
"""
import importlib.util
import math
import os
from pathlib import Path
import sys


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


def coordinate(root, stream, *, sender_identity, runtime_directory, user_environment=None,
               precheck, exclusion, hook_identity, intermediary_identity,
               phase_timeout=10.0, handoff_timeout=1.0, scope_factory=None, recover=None):
  """One fresh handoff/owner scope; caller owns stream, owner owns receipt/children.

  exclusion() is a fixture context yielding a raising power_guard. The supplied
  account environment is snapshotted, passwd-bound and tied to the actual peer
  UID, never an asserted target UID. Returncodes flow to existing exclusive
  phase evidence; a signal/exception is refusal, not a successful phase result.
  A signed observed-exit diagnostic precedes the final gate, but never replaces
  phase success/admission. An interrupted write/wait may still lack durable
  status; no exit record is fabricated for those interruptions.
  Source fixture timeouts are not a production package-update timeout policy.
  scope_factory(held) must return an owner-retained Scope-compatible handle even
  on ambiguous attachment; it never releases/reaps the child. recover(error,
  attempt) is only notification/repair, never a grant or cancellable escape.
  Retained retries ignore callback interruption until observed settlement and
  exact durable veto, independent of a dead initiating client. No live roots.
  """
  root = M._fixture(root)  # BEFORE a handshake, exclusion or caller callback
  if not callable(precheck) or not callable(exclusion) or (user_environment is not None and type(user_environment) is not dict):
    raise ValueError("Explicit fixture exclusion/precheck and user environment required")
  if scope_factory is not None and (not callable(scope_factory) or not callable(recover)):
    raise ValueError("Retained scope requires callable fixture recovery")
  if recover is not None and not callable(recover): raise ValueError("Explicit fixture recovery required")
  if type(phase_timeout) not in (int, float) or not math.isfinite(phase_timeout) or not 0 < phase_timeout <= 30:
    raise ValueError("Explicit bounded fixture phase deadline required")
  H.P._timeout(handoff_timeout)
  environment = None if user_environment is None else dict(user_environment)
  hook, intermediary = dict(hook_identity), dict(intermediary_identity)
  B._identity(hook)
  if set(intermediary) != {"uid", "exe"} or type(intermediary["uid"]) is not int or intermediary["uid"] < 0 or type(intermediary["exe"]) is not str:
    raise ValueError("Exact fixture intermediary UID/executable required")
  _inside(root, runtime_directory)
  if environment is not None:
    if "OMARCHY_PATH" not in environment: raise ValueError("Explicit fixture Omarchy path required")
    _inside(root, environment["OMARCHY_PATH"])
  with exclusion() as power_guard:
    if not callable(power_guard): raise ValueError("Scoped raising fixture power guard required")
    power_guard()
    with H.receive_lock(stream, sender_identity=sender_identity, runtime_directory=runtime_directory,
                        timeout=handoff_timeout, **({"require_environment": True} if environment is None else {})) as receipt:
      if environment is None:
        if type(receipt.environment) is not dict: raise ValueError("Authenticated handoff user context required")
        environment = dict(receipt.environment)
        _inside(root, environment["OMARCHY_PATH"])
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
        scope = None
        ambient_error = sys.exception()
        def settle():
          if scope is None: return
          if sys.exception() is not None and sys.exception() is not ambient_error:
            session.active, session.phase = False, None
          def condition():
            # Drain even if the owner power guard has failed; never use receipt
            # or client watch here. Client death is the reason for recovery.
            if scope.drain() is not True:
              raise RuntimeError("Owned phase scope remains unsettled") from scope.error
            session.physical()
            power_guard()
            if M.T._read(root, (session.archive / "maintenance-intent.json").relative_to(root)) != session.intent:
              raise ValueError("Original archived maintenance intent changed")
            M.T._veto(root, session.intent, durable=True)
          def repair(error, attempt):
            session.active, session.phase = False, None
            recover(error, attempt)
          M.T._retained(condition, repair)
        try:
          if scope_factory is not None:
            scope = scope_factory(held)
            if scope.check_ready() is not True:
              raise RuntimeError("Owned held phase scope not ready") from scope.error
          code = B.run_phase(root, root / HOOK_SOCKET, launch=lambda _: held.process,
            phase_identity=held.identity, release=held.release, owner_identity=owner,
            hook_identity=hook, intermediary_identity=intermediary, gate=gate,
            watch=watch, cancel_fd=receipt.peer.fd, settle=settle if scope is not None else None,
            timeout=phase_timeout)
          if type(code) is not int: raise ValueError("Actual signed integer child status required")
          observed = M.T._encoded({"protocol": "omarchy-t2-package-phase-observed-exit-v1",
            "session_id": session.start["session_id"], "phase": name, "returncode": code})
          path = session.archive / ("package-phase-" + str(M.PHASES.index(name)).zfill(2) + "-" + name + "-observed-exit.json")
          M.T._new(path, observed)
          if M.T._read(root, path.relative_to(root)) != observed: raise ValueError("Observed exit diagnostic readback differs")
          gate()  # includes last phase, INSIDE durable maintenance/physical scope
          return code
        except BaseException:
          session.active, session.phase = False, None
          raise
        finally:
          settle()
          if scope is not None: scope.close()
          # Broker owns the only reaper until it returns/raises. This finalizer
          # closes the launcher's private descriptors even on bad-pin refusal.
          held.abort()

      watch()
      result = M.coordinate(root, precheck=checked_precheck, run_phase=phase, guard=watch, recover=recover)
      watch()
      return result
