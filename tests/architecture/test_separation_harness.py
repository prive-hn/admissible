"""Contract: the sabotage harness itself, judged the way it judges guards.

:mod:`tests.architecture.test_separation_sabotage` asks whether the twelve
separation invariants are load-bearing.  It can only answer that if the
instrument it asks with is sound, and an instrument that reports a kill for the
wrong reason is worse than no instrument: it turns a broken guard into a green
receipt, and a green receipt is what everything downstream reads.

Four ways the instrument could lie are checked here, each by planting a probe
that exhibits the failure on purpose.

*A kill has to be the guard's own assertion.*  ``python -m unittest`` exits
non-zero for a module that will not import, a fixture that raises, a test that
dies of an unrelated exception, and a test that fails an assertion about
something else entirely.  None of those is evidence that the sabotage was
noticed -- they are all evidence that the run never reached the question -- so
each one is registered below as a probe that must come back ``ERROR``.  The
positive probe, whose assertion fails exactly as its signature says it will, is
what keeps the negative ones from being satisfied by a harness that simply
never kills anything.

*A kill has to be the whole outcome, not a matching part of one.*  A test can
fail more than once, and a mutation can break the case the guard is aimed at
and an unrelated case in the same run.  "One of the failures matched" cannot
tell that apart from the sabotage being noticed, so the registry writes down
the exact failures and their exact number, and anything else -- a second copy,
an unrelated failure beside the expected one, a result belonging to another
test -- is an error.

*The subject may not write the evidence.*  The mutated code and the tests
judging it are one process, and it used to be handed the report the harness
would believe.  The probes below are the concrete forgeries: rewriting the
report named in ``sys.argv``, replacing ``json``, ``open`` and ``unittest``'s
result machinery, and emitting a fully-formed record of the failure the parent
is waiting for while the test passes or dies.  None of them may produce a kill.

*A mutant may not reach the developer's machine.*  A mutated build backend or a
mutated test is arbitrary code, and it runs with whatever the harness hands it.
So the probes below read back what a child can actually see -- the names of its
environment, whether a planted file in the caller's ``HOME`` is reachable, what
a socket does -- and require that the answer is a private, offline world rather
than this developer's.  Values are never reported, only names and verdicts:
a probe that printed what it found would be the leak it exists to rule out.
"""
from __future__ import annotations

import base64
import errno
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from . import separation_guards as guards
from . import separation_observer as observer

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Probes are small and must not be allowed to hang a run for a quarter hour.
PROBE_TIMEOUT_SECONDS = 300

_HEADER = '"""Planted by the separation harness contract tests."""\n'


# ---------------------------------------------------------------------------
# Probes that exercise the four ways a run exits non-zero without proving
# anything, plus the assertion that does prove something.

def _probe_module(body: str) -> str:
    return _HEADER + "import unittest\n\n\n" + body


#: The message the positive probe fails with, and the fragment its registered
#: signature looks for.  Written once so the two cannot drift apart.
EXPECTED_MESSAGE = "the planted guard refused a planted separation breach"

IMPORT_ERROR_PROBE = (
    _HEADER
    + "import unittest\n"
    + "import admissible_probe_module_that_no_distribution_ships\n\n\n"
    + "class PlantedGuard(unittest.TestCase):\n"
    + "    def test_the_planted_guard_notices(self):\n"
    + f"        self.fail({EXPECTED_MESSAGE!r})\n"
)

TEST_ERROR_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    '        raise RuntimeError("a planted exception that is not an assertion")\n'
)

FIXTURE_ERROR_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def setUp(self):\n"
    '        raise RuntimeError("a planted fixture that cannot be built")\n'
    "\n"
    "    def test_the_planted_guard_notices(self):\n"
    f"        self.fail({EXPECTED_MESSAGE!r})\n"
)

SYSTEM_EXIT_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        raise SystemExit(3)\n"
)

WRONG_FAILURE_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    '        self.fail("a planted disagreement about an unrelated property")\n'
)

EXPECTED_FAILURE_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    f"        self.fail({EXPECTED_MESSAGE!r})\n"
    "\n"
    "    def test_the_planted_control_stays_green(self):\n"
    "        self.assertTrue(True)\n"
)

BROKEN_CONTROL_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    f"        self.fail({EXPECTED_MESSAGE!r})\n"
    "\n"
    "    def test_the_planted_control_stays_green(self):\n"
    '        raise RuntimeError("the planted control cannot run either")\n'
)

PASSING_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        self.assertTrue(True)\n"
)

_PROBE_PACKAGE = "tests/architecture"


#: What the positive probe's failure looks like when it is described in
#: advance: the exception, and a fragment only that assertion produces.
EXPECTED_SIGNATURE = guards.GuardFailure("AssertionError", (EXPECTED_MESSAGE,))

#: A signature for a failure some *other* guard would produce.  Registering it
#: against the probe below is how "the test went red" and "the test caught this
#: sabotage" are told apart.
WRONG_SIGNATURE = guards.GuardFailure("AssertionError", (
    "the Trust wheel must not contain admissible_ready",))


def probe_mutant(name: str, body: str, *, method: str = None,
                 control: str = None,
                 expects: guards.GuardFailure = EXPECTED_SIGNATURE,
                 ) -> guards.Mutant:
    """A mutant whose whole sabotage is planting one probe module.

    The probe replaces the production edit *and* the guard: nothing real is
    touched, so what comes back is a statement about the harness rather than
    about the product.
    """

    module = f"harness_probe_{name}"
    dotted = f"tests.architecture.{module}.PlantedGuard"
    return guards.Mutant(
        mutant_id=f"PROBE-{name}",
        sep="SEP12",
        shape="guard-removal-is-specifically-detected",
        summary=f"a planted probe module that {name.replace('_', ' ')}",
        edits=(guards.Creation(f"{_PROBE_PACKAGE}/{module}.py", body),),
        kills=f"{dotted}.{method or 'test_the_planted_guard_notices'}",
        expects=expects,
        control=f"{dotted}.{control}" if control else None)


class ANonZeroExitIsNotAKill(unittest.TestCase):
    """Four ways a suite goes red without ever reaching the guard.

    Every one of these makes ``python -m unittest`` exit non-zero after
    printing ``Ran 1 test``, which is all the harness used to look at.  A
    mutation that broke the import of the module holding the guard would then
    be reported as a guard that caught it.
    """

    def evaluate(self, mutant: guards.Mutant) -> guards.Receipt:
        return guards.evaluate(mutant, root=REPO_ROOT,
                               timeout=PROBE_TIMEOUT_SECONDS)

    def assert_error(self, mutant: guards.Mutant) -> guards.Receipt:
        receipt = self.evaluate(mutant)
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)
        return receipt

    def test_a_module_that_will_not_import_is_an_error(self):
        self.assert_error(probe_mutant("import_error", IMPORT_ERROR_PROBE))

    def test_a_test_that_raises_an_unrelated_exception_is_an_error(self):
        self.assert_error(probe_mutant("test_error", TEST_ERROR_PROBE))

    def test_a_fixture_that_cannot_be_built_is_an_error(self):
        self.assert_error(probe_mutant("fixture_error", FIXTURE_ERROR_PROBE))

    def test_a_test_that_exits_the_interpreter_is_an_error(self):
        self.assert_error(probe_mutant("system_exit", SYSTEM_EXIT_PROBE))

    def test_a_control_that_cannot_run_is_an_error(self):
        self.assert_error(probe_mutant(
            "broken_control", BROKEN_CONTROL_PROBE,
            control="test_the_planted_control_stays_green"))

    def test_a_probe_that_does_not_fail_at_all_is_a_survivor(self):
        """The other side of the claim: silence is still reported as silence."""
        receipt = self.evaluate(probe_mutant("passing", PASSING_PROBE))
        self.assertEqual(guards.SURVIVED, receipt.verdict, receipt.detail)

    def test_the_expected_failure_is_still_a_kill(self):
        """The control for every ERROR above.

        Without it, a harness that had simply stopped killing anything would
        satisfy this whole class.
        """
        receipt = self.evaluate(probe_mutant(
            "expected_failure", EXPECTED_FAILURE_PROBE,
            control="test_the_planted_control_stays_green"))
        self.assertEqual(guards.KILLED, receipt.verdict, receipt.detail)
        self.assertIn(EXPECTED_MESSAGE, receipt.detail)


class AFailureHasToBeTheRegisteredOne(unittest.TestCase):
    """A red test is not evidence until it is the *expected* red test.

    The four probes above are ways of never reaching the assertion.  This is
    the subtler one: the assertion runs, the test fails, and it fails about
    something else entirely -- which is what a mutation that broke an unrelated
    property of the same test looks like from the outside.
    """

    def evaluate(self, mutant: guards.Mutant) -> guards.Receipt:
        return guards.evaluate(mutant, root=REPO_ROOT,
                               timeout=PROBE_TIMEOUT_SECONDS)

    def test_a_failure_that_is_not_the_registered_one_is_an_error(self):
        receipt = self.evaluate(probe_mutant(
            "wrong_failure", WRONG_FAILURE_PROBE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)
        self.assertIn("not as AssertionError carrying", receipt.detail)

    def test_a_signature_naming_the_wrong_exception_is_an_error(self):
        receipt = self.evaluate(probe_mutant(
            "wrong_exception", EXPECTED_FAILURE_PROBE,
            expects=guards.GuardFailure("ValueError", (EXPECTED_MESSAGE,))))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)

    def test_a_registered_signature_on_a_real_mutant_can_be_made_wrong(self):
        """The same claim, on a registered mutant rather than a planted one."""
        real = guards.mutants_for("SEP3")[0]
        receipt = self.evaluate(replace(real, expects=WRONG_SIGNATURE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)
        self.assertEqual(guards.KILLED,
                         self.evaluate(real).verdict,
                         "the unaltered mutant must still be killed, or the "
                         "line above proves nothing")


class TheRegisteredSignaturesAreUsableEvidence(unittest.TestCase):
    """The signature data itself, checked before any verdict rests on it."""

    def test_every_registered_signature_is_specific_and_unique(self):
        self.assertEqual([], list(guards.signature_problems()))

    def test_a_generic_signature_is_rejected(self):
        real = guards.mutants_for("SEP3")[0]
        for broken, why in (
                (guards.GuardFailure("AssertionError", ()), "no fragment"),
                (guards.GuardFailure("AssertionError", ("ready",)), "a word"),
                (guards.GuardFailure("", ("something specific enough",)),
                 "no exception"),
        ):
            with self.subTest(why=why):
                self.assertNotEqual(
                    [], list(guards.signature_problems(
                        [replace(real, expects=broken)])))

    def test_two_mutants_may_not_share_one_signature(self):
        first, second = guards.MUTANTS[0], guards.MUTANTS[1]
        shared = replace(second, expects=first.expects)
        self.assertNotEqual(
            [], list(guards.signature_problems([first, shared])))

    def test_a_signature_may_not_be_the_test_s_own_name(self):
        real = guards.mutants_for("SEP3")[0]
        name = real.kills.rpartition(".")[2]
        self.assertNotEqual([], list(guards.signature_problems(
            [replace(real, expects=guards.GuardFailure(
                "AssertionError", (name,)))])))


# ---------------------------------------------------------------------------
# A kill is the whole expected outcome, not one matching record inside it.
#
# A test can fail more than once: a subtest loop reports one failure per case,
# and a mutation is quite capable of breaking the intended case *and* an
# unrelated one in the same run.  "One of the failures matched" is therefore
# not the claim -- from the outside it is indistinguishable from a mutation
# that broke something else and happened to break the guard's case too.  What a
# kill has to mean is that the run produced *exactly* the outcome the mutant
# registered: this test and no other, no error, no skip, and exactly the
# registered number of failures, every one of them the signature's own.

UNRELATED_MESSAGE = "a planted disagreement about an unrelated property"

MIXED_FAILURE_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        with self.subTest(part='the case the guard is aimed at'):\n"
    f"            self.fail({EXPECTED_MESSAGE!r})\n"
    "        with self.subTest(part='an unrelated case'):\n"
    f"            self.fail({UNRELATED_MESSAGE!r})\n"
)

TWICE_EXPECTED_PROBE = _probe_module(
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        for case in ('first', 'second'):\n"
    "            with self.subTest(case=case):\n"
    f"                self.fail({EXPECTED_MESSAGE!r})\n"
)


def _record(test: str, status: str = guards.FAILED_STATUS, *,
            exception: str = "AssertionError", message: str = EXPECTED_MESSAGE,
            subtest: str = "") -> guards.TestRecord:
    return guards.TestRecord(test=test, status=status, exception=exception,
                             message=message, subtest=subtest)


def _outcome(records, *, ran: int = 1, returncode: int = 1) -> guards.Outcome:
    return guards.Outcome(returncode, ran, "planted", records=tuple(records),
                          reported=True)


class AKillIsTheCompleteExpectedOutcome(unittest.TestCase):
    """The rules, read directly, without building a clone for each one."""

    def setUp(self):
        self.mutant = probe_mutant("judged_directly", PASSING_PROBE)
        self.named = self.mutant.kills

    def judge(self, *records, **kwargs) -> tuple[str, str]:
        return guards.judge(self.mutant, _outcome(records, **kwargs))

    def assert_error(self, *records, **kwargs) -> str:
        verdict, detail = self.judge(*records, **kwargs)
        self.assertEqual(guards.ERROR, verdict, detail)
        return detail

    def test_the_registered_failure_on_its_own_is_a_kill(self):
        """The control: without it every rule below is satisfied by silence."""
        verdict, detail = self.judge(_record(self.named))
        self.assertEqual(guards.KILLED, verdict, detail)

    def test_an_unrelated_failure_beside_the_expected_one_is_not_a_kill(self):
        self.assert_error(
            _record(self.named, subtest="the guard's own case"),
            _record(self.named, message=UNRELATED_MESSAGE,
                    subtest="an unrelated case"))

    def test_a_second_copy_of_the_expected_failure_is_not_a_kill(self):
        """One registered failure means one, not "at least one"."""
        self.assert_error(_record(self.named, subtest="first"),
                          _record(self.named, subtest="second"))

    def test_a_record_from_another_test_is_not_a_kill(self):
        self.assert_error(
            _record(self.named),
            _record("tests.architecture.harness_probe_other.Other.test_other",
                    message=UNRELATED_MESSAGE))

    def test_a_passing_record_beside_the_failure_is_not_a_kill(self):
        self.assert_error(_record(self.named),
                          _record(self.named, guards.PASSED_STATUS,
                                  exception="", message=""))

    def test_an_errored_record_beside_the_expected_failure_is_not_a_kill(self):
        self.assert_error(_record(self.named),
                          _record(self.named, guards.ERRORED_STATUS,
                                  exception="RuntimeError",
                                  message=UNRELATED_MESSAGE))

    def test_a_skipped_record_beside_the_expected_failure_is_not_a_kill(self):
        self.assert_error(_record(self.named),
                          _record(self.named, guards.SKIPPED_STATUS,
                                  exception="", message=""))

    def test_a_registered_cardinality_admits_exactly_that_many_failures(self):
        twice = replace(self.mutant, expects=replace(
            self.mutant.expects, count=2))
        verdict, detail = guards.judge(twice, _outcome(
            (_record(self.named, subtest="first"),
             _record(self.named, subtest="second"))))
        self.assertEqual(guards.KILLED, verdict, detail)
        for records in ((_record(self.named),),
                        (_record(self.named, subtest="first"),
                         _record(self.named, subtest="second"),
                         _record(self.named, subtest="third"))):
            with self.subTest(failures=len(records)):
                verdict, detail = guards.judge(twice, _outcome(records))
                self.assertEqual(guards.ERROR, verdict, detail)

    def test_a_registered_cardinality_still_refuses_an_unmatched_failure(self):
        twice = replace(self.mutant, expects=replace(
            self.mutant.expects, count=2))
        verdict, detail = guards.judge(twice, _outcome(
            (_record(self.named, subtest="first"),
             _record(self.named, message=UNRELATED_MESSAGE,
                     subtest="second"))))
        self.assertEqual(guards.ERROR, verdict, detail)


class AMixedFailureRunIsJudgedAsOne(unittest.TestCase):
    """The same claim through a real subprocess, from a real subtest loop."""

    def evaluate(self, mutant: guards.Mutant) -> guards.Receipt:
        return guards.evaluate(mutant, root=REPO_ROOT,
                               timeout=PROBE_TIMEOUT_SECONDS)

    def test_one_expected_and_one_unrelated_failure_is_an_error(self):
        receipt = self.evaluate(probe_mutant("mixed_failure",
                                             MIXED_FAILURE_PROBE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)

    def test_two_expected_failures_where_one_is_registered_is_an_error(self):
        receipt = self.evaluate(probe_mutant("twice_expected",
                                             TWICE_EXPECTED_PROBE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)

    def test_two_expected_failures_registered_as_two_is_a_kill(self):
        """The control: an exact cardinality is a claim, not a refusal."""
        mutant = probe_mutant("twice_expected_registered",
                              TWICE_EXPECTED_PROBE)
        receipt = self.evaluate(replace(
            mutant, expects=replace(mutant.expects, count=2)))
        self.assertEqual(guards.KILLED, receipt.verdict, receipt.detail)


# ---------------------------------------------------------------------------
# What the tested process is not allowed to author.
#
# The mutated code and the tests judging it run in one process, and that
# process used to be handed the report the parent would believe: its path
# arrived in ``sys.argv``, and the document was written with whatever
# ``json.dump`` and ``open`` meant by the time the run ended.  Code that can
# reach any of those can write its own verdict, and a harness that reads a
# verdict its subject wrote is not measuring anything.
#
# The probes below are the concrete forgeries, written as an attacker would:
# they rewrite the report named in argv, they replace the report machinery, and
# they emit a fully-formed record of the failure the parent is waiting for
# while the test itself passes or dies.  None of them may produce a kill.

FORGERY_HEADER = (
    _HEADER
    + "import atexit\n"
      "import base64\n"
      "import builtins\n"
      "import json\n"
      "import os\n"
      "import sys\n"
      "import unittest\n"
      "\n"
      f"MESSAGE = {EXPECTED_MESSAGE!r}\n"
      "FALLBACK_MARKER = '<<<ADMISSIBLE-SEPARATION-RECORD>>>'\n"
      "\n"
      "\n"
      "def forged(test_id):\n"
      "    \"\"\"Exactly the outcome the parent is waiting for, invented.\"\"\"\n"
      "    return {'ran': 1, 'successful': False, 'truncated': False,\n"
      "            'crashed': '',\n"
      "            'records': [{'test': test_id, 'status': 'failed',\n"
      "                         'exception': 'AssertionError',\n"
      "                         'message': MESSAGE, 'subtest': ''}]}\n"
      "\n"
      "\n"
      "def writable_argv_paths():\n"
      "    found = []\n"
      "    for candidate in sys.argv:\n"
      "        if not isinstance(candidate, str) or os.sep not in candidate:\n"
      "            continue\n"
      "        directory = os.path.dirname(candidate)\n"
      "        if os.path.isdir(directory) and os.access(directory, os.W_OK):\n"
      "            found.append(candidate)\n"
      "    return found\n"
      "\n"
      "\n"
      "def overwrite_the_report(test_id):\n"
      "    for path in writable_argv_paths():\n"
      "        try:\n"
      "            with open(path, 'w', encoding='utf-8') as handle:\n"
      "                json.dump(forged(test_id), handle)\n"
      "        except OSError:\n"
      "            pass\n"
      "\n"
      "\n"
      "def the_public_marker():\n"
      "    try:\n"
      "        from tests.architecture import separation_guards\n"
      "        found = getattr(separation_guards, 'RECORD_MARKER', '')\n"
      "        if isinstance(found, str) and found:\n"
      "            return found\n"
      "    except Exception:\n"
      "        pass\n"
      "    main = sys.modules.get('__main__')\n"
      "    for name in dir(main):\n"
      "        found = getattr(main, name, None)\n"
      "        if isinstance(found, str) and found.startswith('<<<ADMISSIBLE'):\n"
      "            return found\n"
      "    return FALLBACK_MARKER\n"
      "\n"
      "\n"
      "def emit_a_forged_frame(test_id):\n"
      "    body = base64.b64encode(json.dumps(forged(test_id)).encode())\n"
      "    os.write(1, the_public_marker().encode() + b' ' + body + b'\\n')\n"
      "\n"
      "\n"
      "def replace_the_report_machinery(test_id):\n"
      "    real_dump, real_dumps = json.dump, json.dumps\n"
      "    json.dump = lambda obj, fp, **kw: real_dump(forged(test_id), fp)\n"
      "    json.dumps = lambda obj, **kw: real_dumps(forged(test_id))\n"
      "    real_open = builtins.open\n"
      "    builtins.open = lambda *a, **kw: real_open(*a, **kw)\n"
      "    unittest.TextTestResult.addSuccess = (\n"
      "        lambda self, test: unittest.TestResult.addSuccess(self, test))\n"
      "\n"
      "\n"
)

ARGV_FORGERY_PROBE = FORGERY_HEADER + (
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        # The report the parent reads is written on the way out, so the\n"
    "        # rewrite is queued for after that as well as attempted now.\n"
    "        atexit.register(overwrite_the_report, self.id())\n"
    "        overwrite_the_report(self.id())\n"
)

MONKEYPATCH_FORGERY_PROBE = FORGERY_HEADER + (
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        replace_the_report_machinery(self.id())\n"
)

FRAME_FORGERY_PROBE = FORGERY_HEADER + (
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        emit_a_forged_frame(self.id())\n"
)

FORGE_AND_DIE_PROBE = FORGERY_HEADER + (
    "class PlantedGuard(unittest.TestCase):\n"
    "    def test_the_planted_guard_notices(self):\n"
    "        atexit.register(overwrite_the_report, self.id())\n"
    "        overwrite_the_report(self.id())\n"
    "        replace_the_report_machinery(self.id())\n"
    "        emit_a_forged_frame(self.id())\n"
    "        raise RuntimeError('the planted guard never reached an assertion')\n"
)

SILENT_EXIT_PROBE = (
    _HEADER
    + "import os\n"
      "import unittest\n"
      "\n"
      "\n"
      "class PlantedGuard(unittest.TestCase):\n"
      "    def test_the_planted_guard_notices(self):\n"
      "        os._exit(0)\n"
)

VISIBILITY_PROBE = (
    _HEADER
    + "import json\n"
      "import os\n"
      "import sys\n"
      "import unittest\n"
      "from pathlib import Path\n"
      "\n"
      "REPORT = Path.cwd() / 'visibility-probe.json'\n"
      "\n"
      "\n"
      "class WhatTheChildIsTold(unittest.TestCase):\n"
      "    def test_report_the_names_this_child_was_given(self):\n"
      "        writable = []\n"
      "        for candidate in sys.argv:\n"
      "            directory = os.path.dirname(candidate)\n"
      "            if directory and os.path.isdir(directory):\n"
      "                writable.append(candidate)\n"
      "        REPORT.write_text(json.dumps({\n"
      "            'argv': list(sys.argv),\n"
      "            'writable_argv_paths': writable,\n"
      "            'environment': sorted(os.environ),\n"
      "            'inherited_descriptors': [fd for fd in range(3, 64)\n"
      "                                      if _openable(fd)],\n"
      "        }), encoding='utf-8')\n"
      "\n"
      "\n"
      "def _openable(fd):\n"
      "    try:\n"
      "        os.fstat(fd)\n"
      "    except OSError:\n"
      "        return False\n"
      "    return True\n"
)


class ATestedProcessCannotAuthorTheEvidence(unittest.TestCase):
    """Forgery, attempted three ways, and refused three ways.

    Each probe here is harmless -- it plants a module of its own and touches
    nothing else -- and each one tries to hand the parent the exact record that
    would be read as "the guard caught the sabotage".  A verdict of ``KILLED``
    from any of them is the harness believing its own subject.
    """

    def evaluate(self, mutant: guards.Mutant) -> guards.Receipt:
        return guards.evaluate(mutant, root=REPO_ROOT,
                               timeout=PROBE_TIMEOUT_SECONDS)

    def test_rewriting_the_report_named_in_argv_cannot_forge_a_kill(self):
        receipt = self.evaluate(probe_mutant("argv_forgery",
                                             ARGV_FORGERY_PROBE))
        self.assertNotEqual(guards.KILLED, receipt.verdict, receipt.detail)
        self.assertEqual(guards.SURVIVED, receipt.verdict, receipt.detail)

    def test_replacing_the_report_machinery_cannot_forge_a_kill(self):
        receipt = self.evaluate(probe_mutant("monkeypatch_forgery",
                                             MONKEYPATCH_FORGERY_PROBE))
        self.assertNotEqual(guards.KILLED, receipt.verdict, receipt.detail)
        self.assertEqual(guards.SURVIVED, receipt.verdict, receipt.detail)

    def test_a_forged_record_frame_is_an_error(self):
        receipt = self.evaluate(probe_mutant("frame_forgery",
                                             FRAME_FORGERY_PROBE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)

    def test_forging_while_dying_of_an_unrelated_exception_is_an_error(self):
        receipt = self.evaluate(probe_mutant("forge_and_die",
                                             FORGE_AND_DIE_PROBE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)

    def test_a_run_that_leaves_no_record_frame_is_an_error(self):
        """A process that ends itself quietly has reported nothing."""
        receipt = self.evaluate(probe_mutant("silent_exit", SILENT_EXIT_PROBE))
        self.assertEqual(guards.ERROR, receipt.verdict, receipt.detail)

    def test_an_honest_probe_is_still_killed(self):
        """The control for the five above, run through the same path."""
        receipt = self.evaluate(probe_mutant("honest_beside_forgeries",
                                             EXPECTED_FAILURE_PROBE))
        self.assertEqual(guards.KILLED, receipt.verdict, receipt.detail)


class TheEvidenceChannelIsNotVisibleToTheChild(unittest.TestCase):
    """What the tested process is told, read back from inside it."""

    def observed(self) -> dict:
        root = Path(tempfile.mkdtemp(prefix="admissible-harness-probe-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / "harness_probe_visibility.py").write_text(
            VISIBILITY_PROBE, encoding="utf-8")
        outcome = guards.run_named_tests(
            root, ["harness_probe_visibility.WhatTheChildIsTold"
                   ".test_report_the_names_this_child_was_given"],
            timeout=PROBE_TIMEOUT_SECONDS)
        self.assertEqual(0, outcome.returncode, outcome.detail)
        return json.loads(
            (root / "visibility-probe.json").read_text(encoding="utf-8"))

    def test_no_argv_entry_names_a_place_the_child_could_write(self):
        observed = self.observed()
        self.assertEqual([], observed["writable_argv_paths"],
                         "a path in argv is a report the subject can rewrite")

    def test_the_child_argv_is_the_test_ids_and_nothing_else(self):
        observed = self.observed()
        self.assertEqual(
            ["-c", "harness_probe_visibility.WhatTheChildIsTold"
                   ".test_report_the_names_this_child_was_given"],
            observed["argv"])

    def test_no_environment_variable_carries_the_channel(self):
        observed = self.observed()
        self.assertEqual(
            [],
            sorted(set(observed["environment"])
                   - set(guards.FORCED_ENVIRONMENT_NAMES)
                   - set(guards.INHERITED_NAMES)
                   - set(guards.BOUNDARY_ADDED_NAMES)))

    def test_the_child_inherits_no_descriptor_beyond_the_standard_three(self):
        observed = self.observed()
        self.assertEqual([], observed["inherited_descriptors"],
                         "an inherited descriptor is a channel the subject "
                         "can write the parent's evidence on")


class TheObserverRefusesAnAmbiguousRun(unittest.TestCase):
    """The observer's own rules, asked directly rather than through a clone.

    Each case here replaces the recorder with three lines that misbehave in one
    specific way, so that "a frame the observer must not accept" is a statement
    with a test rather than a paragraph.  These runners are this suite's own
    code and touch nothing -- they write to their own stdout and exit -- so
    they run without a clone; the boundary belongs to mutants, and there is no
    mutant here.
    """

    def observe(self, runner: str) -> dict:
        root = Path(tempfile.mkdtemp(prefix="admissible-observer-probe-"))
        self.addCleanup(shutil.rmtree, root, True)
        return observer.observe({
            "marker": guards.RECORD_MARKER,
            "timeout": PROBE_TIMEOUT_SECONDS,
            "executable": sys.executable,
            "runner": runner,
            "tests": [],
            "cwd": str(root),
            "environment": guards.scrubbed_environment(private_root=root),
            "record_limit": guards.RECORD_LIMIT,
        })

    def frame(self, payload: dict) -> str:
        body = base64.b64encode(json.dumps(payload).encode()).decode()
        return f"{guards.RECORD_MARKER} {body}"

    def emitting(self, text: str, *, code: int = 1) -> str:
        return (f"import os, sys\nos.write(1, {text!r}.encode())\n"
                f"sys.exit({code})\n")

    def honest_payload(self, *, successful: bool = False) -> dict:
        return {"ran": 1, "successful": successful, "truncated": False,
                "crashed": "", "records": [
                    {"test": "planted.Case.test_one", "status": "failed",
                     "exception": "AssertionError", "message": "planted",
                     "subtest": ""}]}

    def test_one_frame_from_a_run_that_agrees_with_itself_is_read(self):
        """The control: these rules refuse things, they do not refuse."""
        report = self.observe(self.emitting(
            self.frame(self.honest_payload()) + "\n"))
        self.assertEqual("", report["problem"])
        self.assertEqual(1, len(report["records"]))

    def test_a_second_frame_makes_the_run_ambiguous(self):
        one = self.frame(self.honest_payload())
        report = self.observe(self.emitting(one + "\n" + one + "\n"))
        self.assertIn("record frames", report["problem"])

    def test_a_run_that_emits_no_frame_is_a_problem(self):
        report = self.observe(self.emitting("nothing to see here\n"))
        self.assertIn("no record frame", report["problem"])

    def test_a_frame_buried_in_other_output_is_a_problem(self):
        report = self.observe(self.emitting(
            "chatter " + self.frame(self.honest_payload()) + "\n"))
        self.assertIn("embedded", report["problem"])

    def test_a_frame_that_cannot_be_decoded_is_a_problem(self):
        report = self.observe(self.emitting(
            f"{guards.RECORD_MARKER} not-base64-at-all\n"))
        self.assertIn("could not be read", report["problem"])

    def test_a_verdict_the_exit_status_contradicts_is_a_problem(self):
        report = self.observe(self.emitting(
            self.frame(self.honest_payload()) + "\n", code=0))
        self.assertIn("disagree", report["problem"])

    def test_a_result_that_is_not_a_status_is_a_problem(self):
        payload = self.honest_payload()
        payload["records"][0]["status"] = "definitely-failed"
        report = self.observe(self.emitting(self.frame(payload) + "\n"))
        self.assertIn("not a test result", report["problem"])

    def test_a_truncated_account_is_a_problem(self):
        payload = self.honest_payload()
        payload["truncated"] = True
        report = self.observe(self.emitting(self.frame(payload) + "\n"))
        self.assertIn("not the whole", report["problem"])

    def test_a_run_that_did_not_complete_as_a_suite_is_a_problem(self):
        payload = self.honest_payload()
        payload["crashed"] = "RuntimeError: the loader gave up"
        report = self.observe(self.emitting(self.frame(payload) + "\n"))
        self.assertIn("did not complete as a suite", report["problem"])


class TheObserverIsSealedAndOutsideTheTree(unittest.TestCase):
    """What runs as the observer is not what a mutant could have edited."""

    def test_the_observer_the_harness_runs_is_a_copy_outside_any_clone(self):
        with guards.disposable_clone(REPO_ROOT) as clone:
            with guards._sealed_observer() as (directory, script):
                self.assertTrue(script.is_file())
                self.assertFalse(
                    str(script).startswith(str(clone)),
                    "the observer must not be run from the tree under test")
                self.assertFalse(str(script).startswith(str(REPO_ROOT)))
                self.assertEqual(
                    guards.OBSERVER_SOURCE.read_bytes(), script.read_bytes())
                self.assertEqual(0o500, script.stat().st_mode & 0o777)
                self.assertEqual([script.name],
                                 [item.name for item in directory.iterdir()])
        self.assertFalse(directory.exists(), "the sealed copy must not outlive "
                                             "the run it was made for")


class OnlyTheObserverCanAuthenticateAReport(unittest.TestCase):
    """The frame the parent trusts, checked as data.

    The observer is the only process holding the per-run key, and the parent
    accepts exactly one frame carrying that run's nonce.  Everything else --
    a second frame, a rewritten body, another run's key -- is an error rather
    than a report.
    """

    def frame(self, key: bytes, nonce: str, report: dict) -> bytes:
        return guards.sealed_frame(key, nonce, report)

    def test_a_frame_this_run_authenticated_is_read_back(self):
        key, nonce = guards.new_channel_secret()
        report = {"nonce": nonce, "ran": 1, "records": [], "returncode": 0,
                  "tail": "planted", "problem": "", "timed_out": False}
        parsed, problem = guards.report_from_frame(
            self.frame(key, nonce, report), key, nonce)
        self.assertEqual("", problem)
        self.assertEqual(1, parsed["ran"])

    def test_a_frame_signed_with_another_key_is_refused(self):
        key, nonce = guards.new_channel_secret()
        other, _ = guards.new_channel_secret()
        report = {"nonce": nonce, "ran": 1, "records": [], "returncode": 0,
                  "tail": "planted", "problem": "", "timed_out": False}
        _parsed, problem = guards.report_from_frame(
            self.frame(other, nonce, report), key, nonce)
        self.assertIn("authentic", problem)

    def test_a_frame_carrying_another_run_s_nonce_is_refused(self):
        key, nonce = guards.new_channel_secret()
        _key, stale = guards.new_channel_secret()
        report = {"nonce": stale, "ran": 1, "records": [], "returncode": 0,
                  "tail": "planted", "problem": "", "timed_out": False}
        _parsed, problem = guards.report_from_frame(
            self.frame(key, stale, report), key, nonce)
        self.assertIn("nonce", problem)

    def test_a_second_frame_on_the_channel_is_refused(self):
        key, nonce = guards.new_channel_secret()
        report = {"nonce": nonce, "ran": 1, "records": [], "returncode": 0,
                  "tail": "planted", "problem": "", "timed_out": False}
        one = self.frame(key, nonce, report)
        _parsed, problem = guards.report_from_frame(one + one, key, nonce)
        self.assertIn("more than one", problem)

    def test_a_truncated_or_rewritten_frame_is_refused(self):
        key, nonce = guards.new_channel_secret()
        report = {"nonce": nonce, "ran": 1, "records": [], "returncode": 0,
                  "tail": "planted", "problem": "", "timed_out": False}
        one = self.frame(key, nonce, report)
        for label, damaged in (("empty", b""),
                               ("no fields", b"nonsense\n"),
                               ("body rewritten", one[:-6] + b"AAAAA\n")):
            with self.subTest(frame=label):
                _parsed, problem = guards.report_from_frame(
                    damaged, key, nonce)
                self.assertNotEqual("", problem)


# ---------------------------------------------------------------------------
# What a mutant's child process can see.

ENVIRONMENT_PROBE = (
    _HEADER
    + "import json\n"
    "import os\n"
    "import unittest\n"
    "from pathlib import Path\n"
    "\n"
    "REPORT = Path.cwd() / 'environment-probe.json'\n"
    "CANARY = 'harness-canary-credentials'\n"
    "MARKER = 'admissible-harness-canary-value'\n"
    "\n"
    "\n"
    "class AmbientEnvironment(unittest.TestCase):\n"
    "    def test_report_what_this_child_can_see(self):\n"
    "        home = Path(os.path.expanduser('~'))\n"
    "        REPORT.write_text(json.dumps({\n"
    "            'names': sorted(os.environ),\n"
    "            'marked': sorted(name for name, value in os.environ.items()\n"
    "                             if value == MARKER),\n"
    "            'home_is_writable': os.access(home, os.W_OK),\n"
    "            'home_canary_visible': (home / CANARY).exists(),\n"
    "        }), encoding='utf-8')\n"
)

#: The value every seeded canary carries.  The probe reports which *names* hold
#: it, never what any variable actually contains, so the leak can be proved
#: absent without a single ambient value being read or printed.
CANARY_MARKER = "admissible-harness-canary-value"

NETWORK_PROBE = (
    _HEADER
    + "import errno\n"
    "import json\n"
    "import socket\n"
    "import unittest\n"
    "from pathlib import Path\n"
    "\n"
    "REPORT = Path.cwd() / 'network-probe.json'\n"
    "TARGETS = {'loopback': ('127.0.0.1', 9),\n"
    "           'non_loopback': ('203.0.113.1', 80)}\n"
    "\n"
    "\n"
    "class OutboundSockets(unittest.TestCase):\n"
    "    def test_report_what_this_child_can_reach(self):\n"
    "        observed = {}\n"
    "        for label, address in TARGETS.items():\n"
    "            probe = socket.socket()\n"
    "            probe.settimeout(2)\n"
    "            try:\n"
    "                probe.connect(address)\n"
    "                observed[label] = 'CONNECTED'\n"
    "            except OSError as error:\n"
    "                observed[label] = errno.errorcode.get(\n"
    "                    error.errno, 'NO_ERRNO')\n"
    "            finally:\n"
    "                probe.close()\n"
    "        REPORT.write_text(json.dumps(observed), encoding='utf-8')\n"
)

#: Names a denylist does not think of.  None of them is a real credential:
#: each points at a file this suite planted, or carries the word ``neutral``.
#: They are here because the question is not whether a particular secret is
#: caught, it is whether anything at all is inherited.
AMBIENT_CANARIES = (
    "NETRC", "KUBECONFIG", "GNUPGHOME", "CLOUDSDK_CONFIG",
    "REQUESTS_CA_BUNDLE", "HARNESS_NEUTRAL_CANARY",
    # The two the boundary program supplies itself. They are seeded here too,
    # so "the child has an LC_CTYPE" is separated from "the child has *this*
    # LC_CTYPE".
    *guards.BOUNDARY_ADDED_NAMES,
)


class AChildSeesAPrivateWorld(unittest.TestCase):
    """No ambient variable, no real HOME, and no socket."""

    def planted_root(self, module: str, body: str) -> Path:
        root = Path(tempfile.mkdtemp(prefix="admissible-harness-probe-"))
        self.addCleanup(shutil.rmtree, root, True)
        (root / f"{module}.py").write_text(body, encoding="utf-8")
        return root

    def run_probe(self, module: str, body: str, dotted: str,
                  report: str) -> dict:
        root = self.planted_root(module, body)
        outcome = guards.run_named_tests(
            root, [f"{module}.{dotted}"], timeout=PROBE_TIMEOUT_SECONDS)
        self.assertEqual(0, outcome.returncode, outcome.detail)
        return json.loads((root / report).read_text(encoding="utf-8"))

    def seeded_environment(self):
        """A caller's environment carrying canaries and a private HOME."""

        home = Path(tempfile.mkdtemp(prefix="admissible-harness-home-"))
        self.addCleanup(shutil.rmtree, home, True)
        (home / "harness-canary-credentials").write_text(
            "planted by the harness contract tests; not a credential\n",
            encoding="utf-8")
        seeded = {name: CANARY_MARKER for name in AMBIENT_CANARIES}
        seeded["HOME"] = str(home)
        return home, seeded

    def observed_child(self) -> dict:
        """What a child sees, with every canary set in this process first."""

        _home, seeded = self.seeded_environment()
        with mock.patch.dict(os.environ, seeded):
            return self.run_probe(
                "harness_probe_environment", ENVIRONMENT_PROBE,
                "AmbientEnvironment.test_report_what_this_child_can_see",
                "environment-probe.json")

    def test_no_ambient_variable_reaches_a_mutant_child(self):
        observed = self.observed_child()
        for name in AMBIENT_CANARIES:
            if name in guards.BOUNDARY_ADDED_NAMES:
                continue
            with self.subTest(variable=name):
                # Reported as a name and a verdict.  The whole point of this
                # suite is that ambient values do not travel, so it does not
                # print the ones it found either.
                self.assertTrue(
                    name not in observed["names"],
                    f"{name} was inherited by the child")

    def test_no_ambient_value_reaches_a_mutant_child_under_any_name(self):
        """Including the two names the boundary program supplies itself.

        ``sandbox-exec`` gives its child an ``LC_CTYPE``, so absence of the
        name proves nothing there.  Absence of the *value* does.
        """
        observed = self.observed_child()
        self.assertEqual([], observed["marked"],
                         "a value seeded in this process reached the child")

    def test_the_child_environment_is_exactly_what_the_harness_owns(self):
        """Not merely "the canaries are gone": nothing else got through either."""
        observed = self.observed_child()
        unexpected = sorted(
            set(observed["names"])
            - set(guards.FORCED_ENVIRONMENT_NAMES)
            - set(guards.INHERITED_NAMES)
            - set(guards.BOUNDARY_ADDED_NAMES))
        self.assertEqual([], unexpected)

    def test_the_child_home_is_private_and_carries_no_planted_file(self):
        observed = self.observed_child()
        self.assertFalse(observed["home_canary_visible"],
                         "a file in the caller's HOME reached the child")
        self.assertTrue(observed["home_is_writable"],
                        "the private HOME must be usable, not merely absent")

    def test_a_planted_home_file_is_readable_without_the_harness(self):
        """The control: the canary is real, so its absence above means something."""
        home, _seeded = self.seeded_environment()
        self.assertTrue((home / "harness-canary-credentials").is_file())

    def test_no_socket_leaves_a_mutant_child(self):
        observed = self.run_probe(
            "harness_probe_network", NETWORK_PROBE,
            "OutboundSockets.test_report_what_this_child_can_reach",
            "network-probe.json")
        for label, verdict in sorted(observed.items()):
            with self.subTest(target=label):
                self.assertIn(verdict, ("EPERM", "EACCES"),
                              "the boundary must refuse the socket itself, "
                              "not leave it to the network to time out")

    def test_the_same_socket_is_not_refused_outside_the_boundary(self):
        """The control: EPERM above is the boundary, not this machine's routing.

        A loopback connection to a closed port is refused everywhere.  What
        distinguishes the boundary is *how*: outside it the network answers,
        inside it the call is never made.  If this machine reported EPERM here
        too, the assertion above would be measuring nothing.
        """
        probe = socket.socket()
        probe.settimeout(2)
        try:
            probe.connect(("127.0.0.1", 9))
        except OSError as error:
            self.assertNotIn(errno.errorcode.get(error.errno),
                             ("EPERM", "EACCES"))
        finally:
            probe.close()

    def test_extra_environment_cannot_reintroduce_a_dangerous_name(self):
        for name in ("HOME", "GITHUB_TOKEN", "PYTHONPATH", "https_proxy",
                     "NETRC", "GIT_CONFIG_GLOBAL"):
            with self.subTest(variable=name):
                with self.assertRaises(guards.MutationError):
                    guards.scrubbed_environment({name: "anything"})

    def test_a_harness_owned_extra_is_accepted_and_validated(self):
        environment = guards.scrubbed_environment({"PYTHONWARNINGS": "error"})
        self.assertEqual("error", environment["PYTHONWARNINGS"])
        with self.assertRaises(guards.MutationError):
            guards.scrubbed_environment({"PYTHONWARNINGS": "a\nb"})


if __name__ == "__main__":  # pragma: no cover - convenience only
    unittest.main()
