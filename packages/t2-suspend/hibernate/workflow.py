"""Offline integration of retained continuity, ledger and immutable byte archive.

All power/capture/cleanup/health behavior is explicitly injected. No CLI, host
sampler, default power writer, EFI or module operation exists. The ledger lock
is held across callbacks to compare the exact prepared cycle and qualification.
This bounded adapter stops at archived: it grants no slot clearing, next-cycle
reconciliation, hardware qualification or physical-test authority. Production
integration must independently audit provenance and callback implementations.
"""

import importlib.util
import json
from pathlib import Path


def _module(name, filename):
  spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
  result = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(result)
  return result


CONTINUITY = _module("workflow_continuity", "continuity.py")
ARCHIVE = _module("workflow_archive", "evidence_archive.py")
TX = CONTINUITY.TX


def encoded(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _archive_bytes(proposal):
  witness = proposal["witness"]
  capture = witness["capture"]
  prefix = proposal["prepared_cycle"]["prefix"]
  def raw(value):
    CONTINUITY.fields(value, ("raw_hex",), "Framed captured bytes")
    return bytes.fromhex(value["raw_hex"])
  markers = capture["markers"]
  return {"source-stage.bin": raw(markers[CONTINUITY.SOURCE_VARIABLE]),
          "restore-stage.bin": raw(markers[CONTINUITY.RESTORE_VARIABLE]),
          "restore-hook-entered.bin": raw(markers["OmarchyT2RestoreHookEntered" + prefix + "-" + CONTINUITY.GUID]),
          "restore-hook-armed.bin": raw(markers["OmarchyT2RestoreHookArmed" + prefix + "-" + CONTINUITY.GUID]),
          "consumed-guard.bin": raw(capture["consumed_guard"]),
          "consumed-attempt.bin": raw(capture["consumed_attempt"]),
          "source-return-witness.bin": encoded(witness),
          "cleanup-health.bin": encoded(witness["cleanup_health"])}


def run(ledger, collector, archive_directory, *, power_write, capture, cleanup, health):
  """Execute only injected behavior and durably record validated return/archive.

  ``collector`` must be this module's actual retained Collector, never a JSON
  proposal. Cleanup always runs after entering the locked callback, including
  write/capture failures. Health runs after cleanup. Failed or interrupted
  persistence leaves an incomplete or failure-blocked cycle; no retry API exists.
  Callbacks and original-process Python state remain trusted, not authenticated.
  """
  if type(collector) is not CONTINUITY.Collector:
    raise ValueError("Actual retained original-process collector required")
  cycle = collector.prepared_cycle()
  def execute(advance):
    phase = "before-write"
    sampled_health = None
    cleanup_errors = None
    failure = None
    def snapshot():
      return CONTINUITY.json_evidence({"schema": "omarchy-t2-product-workflow-snapshot-v1", "phase": phase,
                                      "retained": collector.retained_evidence(), "cleanup_health": sampled_health,
                                      "cleanup_errors": cleanup_errors})
    try:
      collector.claim_workflow()
      ledger._write("workflow-before-" + cycle["cycle_id"] + ".json", snapshot(), exclusive=True)
      phase = "write-and-capture"
      collector.write_and_capture(power_write, capture)
      phase = "captured-before-cleanup"
      ledger._write("workflow-capture-" + cycle["cycle_id"] + ".json", snapshot(), exclusive=True)
    except BaseException as error:
      failure = error
    finally:
      try:
        cleanup_errors = cleanup()
        CONTINUITY.exact(cleanup_errors, [], "Workflow cleanup errors")
      except BaseException as error:
        if failure is None:
          failure = error
    try:
      if failure is not None:
        raise failure
      phase = "post-cleanup-health"
      sampled_health = health(collector.binding)
      ledger._write("workflow-health-" + cycle["cycle_id"] + ".json", snapshot(), exclusive=True)
      proposal = collector.returned_transition(sampled_health, cleanup_errors)
      CONTINUITY.exact(proposal["prepared_cycle"], cycle, "Retained prepared cycle")
      evidence = _archive_bytes(proposal)
      witness_sha256 = CONTINUITY.raw_digest(evidence["source-return-witness.bin"])
      CONTINUITY.exact(witness_sha256, proposal["evidence_sha256"], "Computed witness receipt")
      phase = "recording-return"
      returned = advance("returned", witness_sha256)
      phase = "creating-archive"
      receipt = ARCHIVE.create_archive(archive_directory, returned, evidence)
      phase = "verifying-archive"
      verified = ARCHIVE.verify_archive(archive_directory, returned, receipt["manifest_sha256"])
      CONTINUITY.exact(verified, receipt, "Durable archive readback")
      phase = "recording-archive"
      archived = advance("archive", verified["manifest_sha256"])
      return {"cycle": archived, "archive_receipt": verified, "slot_clear_authorized": False,
              "hardware_qualified": False, "usable_hibernation_qualified": False}
    except BaseException as error:
      # A persistence failure may prevent even this failure journal. The existing
      # incomplete cycle still refuses new allocation; no evidence is deleted.
      failure_record = {"schema": "omarchy-t2-product-workflow-failure-v1", "cycle_id": cycle["cycle_id"],
                        "phase": phase, "error_type": type(error).__name__}
      try:
        failure_record["snapshot"] = snapshot()
        ledger._write("workflow-failure-" + cycle["cycle_id"] + ".json", failure_record, exclusive=True)
      except BaseException as persistence_error:
        error.add_note("Failure evidence persistence also failed: " + type(persistence_error).__name__)
        failure_record.pop("snapshot", None)
      try:
        advance("failed", TX.digest(failure_record))
      except BaseException as latch_error:
        error.add_note("Failure latch could not persist; cycle remains incomplete: " + type(latch_error).__name__)
      raise
  return ledger.compare_and_run(cycle, execute)
