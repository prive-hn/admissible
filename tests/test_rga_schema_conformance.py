"""Every event the RGA and calibration kernels emit validates against the
protocol schemas, and every event type in each schema's enum is exercised.

The schemas restate metrics/SCHEMA.md; a kernel field the schema does not
know, or a schema field the kernel never emits, is a contract drift this
test exists to catch. Events are validated through a JSON round-trip because
the contract is about the serialized journal (tuples become arrays).
Guarded with skipUnless so a pure-stdlib run skips rather than fails.
"""
from __future__ import annotations

import json
import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

try:
    from jsonschema import Draft202012Validator
    _HAVE_JSONSCHEMA = True
except ImportError:  # pragma: no cover
    _HAVE_JSONSCHEMA = False

from protocol import schema_path  # noqa: E402
from fcd.journal import to_plain_json  # noqa: E402
from rga.core import DefectModel, LedgerEntry, Refuter  # noqa: E402
from test_rga_calibration import CalHarness  # noqa: E402
from test_rga_invariants import Harness, ledger  # noqa: E402


def _drive_everything() -> tuple[list[dict], list[dict]]:
    """One run that exercises every rga_* and cal_* event type."""
    # sealed line with escape, adjudication, exclusion, install, audit
    h = CalHarness(e_max=0, gate="seal")
    h.declare_tests()
    h.a.declare(Refuter("pbt", "v9", "tester", "bounded"))
    h.a.bound("pbt", "v9", 0.1, 20)                                   # rga_bound
    h.seal_line("w")                                                  # seal + stamp
    # audit before the escape (checker must be pinned)
    seal = h.a.sealed["w"]
    from rga.core import derive_seed
    aseed = derive_seed("a1", seal.artifact_hash, "tests", "v1", "tests_pass")
    arun = h.cal.file_audit("w", "tests_pass", "tests", "v1", "a1", b"w-body-0", aseed, "ok", "aud")
    h.cal.replay_run(arun.index, "survived", "ok")
    # a second line opened BEFORE the demotion crossing, sealed after it
    h.fcd_open("x"); h.cal.open("x", "gen", "temp=0.7")
    for i in range(h.k):
        h.fcd_write("x"); h.sample("x", f"x-body-{i}".encode()); h.trial("x", i)
    h.replay_all("x"); h.fcd_check("x")
    # tier-A escape -> impeach + demotion crossing (e_max=0)
    run = h.tier_a_escape()                                           # cal_run + cal_replay
    # tier-B escape adjudicated
    h.a.declare(Refuter("hawk", "v1", "hawk-author", "ledger"))
    b = h.cal.file_escape("w", "tests_pass", "hawk", "v1", "n", b"w-body-0", "s", "hk", "aud")
    h.cal.replay_run(b.index, "refuted", "hk")
    h.cal.adjudicate(b.index, "owner", "reject", "not the claim")     # cal_adjudicate
    try:
        h.cal.seal("x")                                               # cal_close E5
    except ValueError:
        pass
    # exclusion + ratchet install
    h.cal.exclude("impl", [run.index], "owner", "class retired")      # cal_exclude
    from test_rga_invariants import admission_policy
    h.cal.install(admission_policy(version="r2"))                     # cal_install
    # discredit: a diverging replay on a fresh checker's run
    h.a.declare(Refuter("flaky", "v1", "someone", "ledger"))
    f = h.cal.file_escape("w", "tests_pass", "flaky", "v1", "n2", b"w-body-0", "s2", "fw", "aud")
    h.cal.replay_run(f.index, "refuted", "different")                 # cal_discredit
    rga_events, cal_events = list(h.a.events), list(h.cal.events)

    # separate RGA-only flows for the remaining rga_* types
    g = Harness(theta=1.0)
    g.declare_tests()
    g.fcd_open(); g.rga_open(); g.fcd_write(); g.sample(); g.trial(verdict="refuted")   # V1 close
    g2 = Harness(theta=1.0)
    g2.declare_tests()
    g2.run_to_seal_ready(witnesses=["w-a", "w-a", "w-b"])
    try:
        g2.a.seal("w")                                                # V2 close
    except ValueError:
        pass
    g3 = Harness()
    g3.declare_tests()
    g3.fcd_open(); g3.rga_open(); g3.fcd_write(); g3.sample(); g3.trial()
    g3.a.replay("w", 0, "refuted", "w-same")                          # rga_refuse + V4
    rga_events += g.a.events + g2.a.events + g3.a.events
    return rga_events, cal_events


@unittest.skipUnless(_HAVE_JSONSCHEMA, "jsonschema not installed (stdlib-only run)")
class RgaSchemaConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rga_events, cls.cal_events = _drive_everything()
        cls.rga_schema = json.loads(schema_path("rga-journal-event.schema.json").read_text())
        cls.cal_schema = json.loads(schema_path("calibration-journal-event.schema.json").read_text())
        Draft202012Validator.check_schema(cls.rga_schema)
        Draft202012Validator.check_schema(cls.cal_schema)

    def _validate(self, events, schema):
        validator = Draft202012Validator(schema)
        for ev in events:
            serialized = to_plain_json(ev)
            errors = sorted(validator.iter_errors(serialized), key=str)
            self.assertFalse(errors, f"{ev.get('type')}: {[e.message for e in errors[:3]]}")

    def test_every_emitted_rga_event_validates(self):
        self._validate(self.rga_events, self.rga_schema)

    def test_every_emitted_calibration_event_validates(self):
        self._validate(self.cal_events, self.cal_schema)

    def test_malformed_events_are_rejected(self):
        """if/then only bites when the discriminator matches — prove the
        variants actually constrain: a wrong-typed field, a missing required
        field, an out-of-enum value and an unknown type must all FAIL."""
        rga = Draft202012Validator(self.rga_schema)
        cal = Draft202012Validator(self.cal_schema)
        good_replay = next(e for e in self.rga_events if e["type"] == "rga_replay")
        good_run = next(e for e in self.cal_events if e["type"] == "cal_run")
        plain_run = to_plain_json(good_run)
        cases = [
            (rga, {**good_replay, "verdict": "maybe"}),
            (rga, {**good_replay, "diverged": "no"}),
            (rga, {k: v for k, v in good_replay.items() if k != "trial_index"}),
            (rga, {"type": "rga_teleport"}),
            (cal, {**plain_run, "tier": "C"}),
            (cal, {**plain_run, "verdict": "maybe"}),
            (cal, {k: v for k, v in plain_run.items()
                   if k != "seed"}),
            (cal, {"type": "cal_wish"}),
        ]
        for validator, ev in cases:
            ev = to_plain_json(ev)
            self.assertFalse(validator.is_valid(ev), f"accepted malformed: {ev}")

    def test_every_schema_event_type_is_exercised(self):
        rga_types = {e["type"] for e in self.rga_events}
        cal_types = {e["type"] for e in self.cal_events}
        self.assertEqual(rga_types, set(self.rga_schema["properties"]["type"]["enum"]))
        self.assertEqual(cal_types, set(self.cal_schema["properties"]["type"]["enum"]))


if __name__ == "__main__":
    unittest.main()
