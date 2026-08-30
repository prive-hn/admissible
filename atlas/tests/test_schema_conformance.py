"""Schema conformance: the reducer's to_dict() output validates against
protocol/atlas-snapshot.schema.json, and real fcd events validate against
protocol/journal-event.schema.json.

Guarded with skipUnless so a pure-stdlib run (no jsonschema installed) skips
rather than errors. The core reducer stays stdlib-only; this test is an
optional cross-check of the language-neutral contract.
"""
from __future__ import annotations

import json
import os
import unittest

from fcd.core import Enforcer, Policy
from fcd.journal import to_plain_json
from atlas.model import build_snapshot

try:
    from jsonschema import Draft202012Validator
    _HAVE_JSONSCHEMA = True
except Exception:  # pragma: no cover
    _HAVE_JSONSCHEMA = False

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PROTO = os.path.join(_ROOT, "protocol")


def _schema(name: str) -> dict:
    with open(os.path.join(_PROTO, name)) as fh:
        return json.load(fh)


def _real_run() -> tuple[list[dict], object]:
    pol = Policy(
        allow={"impl": {"alice", "carol"}, "solo": {"alice"}},
        deny={"impl": set(), "solo": set()},
        phi={"alice": "vendorA:model-a", "carol": "vendorC:model-c", "bob": "vendorB:model-b"},
        required={"impl": [("write", "w1"), ("check", "c1")], "solo": [("write", "w1")]},
        version="v1",
    )
    e = Enforcer(pol, clock=lambda: 0.0)
    for iid, deps in (("A", ()), ("B", ("A",))):
        e.open(iid, "impl", f"hash-{iid}", depends_on=deps)
        e.admit(iid, "alice"); e.bind(iid, True); e.observe(iid, "vendorA:model-a"); e.decide_pass(iid)
        e.admit(iid, "carol"); e.bind(iid, True); e.observe(iid, "vendorC:model-c"); e.decide_pass(iid)
    e.open("D", "solo", "hash-D")
    e.admit("D", "alice"); e.bind("D", True); e.observe("D", "vendorX:wrong"); e.decide_pass("D"); e.no_admit("D")
    snap = build_snapshot(
        list(e.events), policies=pol,
        plan=[{"id": "F", "class": "impl", "label": "downstream", "depends_on": ["D"]}],
        questions=[{"id": "q1", "node_id": "D", "text": "replace dead bind?"}],
        artifacts=[{"id": "art-A", "node_id": "A", "kind": "python_module",
                    "uri": "atlas/model.py", "present": True, "runnable": True}],
        generated_at=7.0,
    )
    return list(e.events), snap


@unittest.skipUnless(_HAVE_JSONSCHEMA, "jsonschema not installed (stdlib-only run)")
class SchemaConformanceTests(unittest.TestCase):
    def test_snapshot_validates(self) -> None:
        events, snap = _real_run()
        schema = _schema("atlas-snapshot.schema.json")
        Draft202012Validator.check_schema(schema)
        errs = list(Draft202012Validator(schema).iter_errors(snap.to_dict()))
        self.assertEqual(errs, [], [e.message for e in errs])

    def test_journal_events_validate(self) -> None:
        events, _ = _real_run()
        schema = _schema("journal-event.schema.json")
        Draft202012Validator.check_schema(schema)
        v = Draft202012Validator(schema)
        for ev in events:
            errs = list(v.iter_errors(to_plain_json(ev)))
            self.assertEqual(errs, [], (ev, [e.message for e in errs]))

    def test_all_protocol_schemas_are_valid_2020_12(self) -> None:
        for name in ("atlas-snapshot.schema.json", "command.schema.json",
                     "evidence-record.schema.json", "journal-event.schema.json",
                     "head-receipt.schema.json", "admissibility-receipt.schema.json"):
            Draft202012Validator.check_schema(_schema(name))


if __name__ == "__main__":
    unittest.main()
