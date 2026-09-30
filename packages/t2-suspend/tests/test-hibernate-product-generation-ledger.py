"""Product ledger continuity across a requalified generation: synthetic cycles in a tempdir; no host, EFI or power operation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

HERE = Path(__file__).resolve().parents[1]


def load(name, filename):
  spec = importlib.util.spec_from_file_location(name, filename)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


PRODUCT = load("generation_ledger_product", HERE / "hibernate/product.py")
TX = PRODUCT.TX


def manifest(tag):
  pins = {name: hashlib.sha256((tag + name).encode()).hexdigest() for name in TX.PINS}
  return {"protocol": TX.PROTOCOL, "model": "MacBookAir9,1", **pins}


def receipt(value, tag="evidence"):
  return {"protocol": TX.PROTOCOL, "manifest_sha256": TX.digest(value), "evidence_sha256": hashlib.sha256(tag.encode()).hexdigest(), "qualified": True}


def evidence(name): return hashlib.sha256(name.encode()).hexdigest()


class GenerationLedger(unittest.TestCase):
  def setUp(self):
    self.temp = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp.cleanup)
    self.directory = Path(self.temp.name) / "ledger"
    self.ledger = TX.Ledger(self.directory)
    self.old, self.new = manifest("generation-1"), manifest("generation-2")

  def cycle(self, value, *, finish=True):
    """One complete synthetic cycle for the currently configured manifest; returns its final record."""
    self.ledger.configure(value)
    self.ledger.qualify(receipt(value))
    cycle = self.ledger.begin(str(uuid.uuid4()))
    if not finish: return cycle
    for action in ("prepared", "returned", "archive", "release", "reconcile"): cycle = self.ledger.advance(cycle["cycle_id"], action, evidence(action + cycle["cycle_id"]))
    self.assertEqual(cycle["state"], "reconciled")
    return cycle

  def links(self): return sorted(path.name for path in self.directory.glob("allocation-*.json") if path.name != "allocation-head.json")

  def test_the_first_cycle_under_a_new_manifest_extends_the_predecessor_chain(self):
    first = self.cycle(self.old)
    state, head = PRODUCT._head(self.ledger)
    self.assertEqual((head["cycle_id"], state["manifest"]), (first["cycle_id"], self.old))
    self.ledger.configure(self.new)  # rebind: the routine product reconfigures its ledger for the new generation
    state, head = PRODUCT._head(self.ledger)
    self.assertEqual((state["manifest"], state["qualification"], state["blocked"]), (self.new, None, False))  # authority is dropped until re-issued
    self.assertEqual(head["cycle_id"], first["cycle_id"])  # the terminal old cycle is still the exact predecessor head
    second = self.cycle(self.new)
    self.assertNotEqual(second["manifest"], first["manifest"])
    self.assertEqual(second["qualification_sha256"], TX.digest(receipt(self.new)))
    link = self.ledger._read("allocation-" + second["cycle_id"] + ".json")
    self.assertEqual(link["predecessor"], {"cycle_id": first["cycle_id"], "cycle_sha256": TX.digest(first)})
    self.assertEqual(link["cycle_binding"]["manifest"], self.new)
    state, head = PRODUCT._head(self.ledger)
    self.assertEqual(head["cycle_id"], second["cycle_id"])
    self.assertEqual(len(self.links()), 2)
    # the ledger's own reader accepts the whole chain and names the old cycle as the new one's predecessor
    self.assertEqual(self.ledger.predecessor(second)["cycle_id"], first["cycle_id"])

  def test_a_third_cycle_under_the_new_manifest_chains_to_the_second(self):
    first = self.cycle(self.old)
    second = self.cycle(self.new)
    third = self.cycle(self.new)
    chain = [self.ledger._read("allocation-" + item["cycle_id"] + ".json")["predecessor"] for item in (third, second, first)]
    self.assertEqual([item and item["cycle_id"] for item in chain], [second["cycle_id"], first["cycle_id"], None])
    self.assertEqual(PRODUCT._head(self.ledger)[1]["cycle_id"], third["cycle_id"])

  def test_reconfiguring_never_rewrites_or_deletes_an_existing_cycle_or_link(self):
    first = self.cycle(self.old)
    before = {path.name: path.read_bytes() for path in self.directory.glob("*") if path.name not in ("state.json", "lock")}
    self.ledger.configure(self.new)
    self.ledger.qualify(receipt(self.new))
    after = {path.name: path.read_bytes() for path in self.directory.glob("*") if path.name not in ("state.json", "lock")}
    self.assertEqual(after, before)
    self.assertEqual(json.loads(before["cycle-" + first["cycle_id"] + ".json"])["manifest"], self.old)

  def test_an_active_or_unreconciled_old_cycle_blocks_the_new_generation(self):
    self.cycle(self.old, finish=False)  # reserved, never completed
    self.ledger.configure(self.new)
    with self.assertRaisesRegex(ValueError, "active, failed or ambiguous"): PRODUCT._head(self.ledger)
    self.ledger.qualify(receipt(self.new))
    with self.assertRaisesRegex(ValueError, "previous cycle is active"): self.ledger.begin(str(uuid.uuid4()))

  def test_a_failure_block_survives_reconfiguration_and_needs_external_reconciliation(self):
    cycle = self.cycle(self.old, finish=False)
    self.ledger.advance(cycle["cycle_id"], "failed", evidence("failed"))
    self.ledger.configure(self.new)
    self.assertTrue(self.ledger._state()["blocked"])
    with self.assertRaisesRegex(ValueError, "Failure blocks qualification"): self.ledger.qualify(receipt(self.new))
    with self.assertRaisesRegex(ValueError, "failure-blocked"): PRODUCT._head(self.ledger)

  def test_qualification_bound_to_another_manifest_is_refused_after_reconfiguration(self):
    self.cycle(self.old)
    self.ledger.configure(self.new)
    with self.assertRaisesRegex(ValueError, "not bound to this product manifest"): self.ledger.qualify(receipt(self.old))
    self.ledger.qualify(receipt(self.new))

  def test_a_stale_old_generation_cycle_record_is_not_admitted_as_the_new_generations_own(self):
    first = self.cycle(self.old)
    self.ledger.configure(self.new)
    self.ledger.qualify(receipt(self.new))
    with self.assertRaisesRegex(ValueError, "qualification changed|Predecessor"): self.ledger.predecessor(first)  # the old head is not a same-manifest predecessor

  def test_a_tampered_predecessor_link_is_refused_when_the_new_generation_starts(self):
    first = self.cycle(self.old)
    second = self.cycle(self.new)
    path = self.directory / ("cycle-" + first["cycle_id"] + ".json")
    tampered = json.loads(path.read_text())
    tampered["original_boot_id"] = str(uuid.uuid4())
    path.write_text(json.dumps(tampered, sort_keys=True))
    with self.assertRaises(ValueError): PRODUCT._head(self.ledger)


if __name__ == "__main__": unittest.main()
