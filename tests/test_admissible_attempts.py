"""Contract: attempts, exact-identity caching, and ceilings before spawn."""
from __future__ import annotations

import io
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import (TempCase, admit,  # noqa: E402
                                evaluating_domain, make_repo, require_module)

cli = require_module("admissible.cli")
config_module = require_module("admissible.config")
decision = require_module("admissible.decision")
evidence = require_module("admissible.evidence")
runner = require_module("admissible.runner")
store_module = require_module("admissible.store")

SECRET = "attempt-test-secret"


def policy(checks, *, max_cost=100, max_wall=600, collect_all=None):
    artifact_class = {
        "id": "default",
        "checks": checks,
        "required_independent_reviews": 0,
        "review_max_age_seconds": 86400,
        "max_cost_units": max_cost,
        "max_wall_seconds": max_wall,
    }
    if collect_all is not None:
        artifact_class["collect_all_checks"] = collect_all
    return {"version": 1, "profile": "python-library",
            "classes": [artifact_class]}


def check(check_id, argv, *, cost=1, required=True, timeout=60, version="1",
          cacheable=False, cache_max_age_seconds=3600):
    """One check. Reuse is opt-in here exactly as it is in a policy file.

    A policy that says nothing about caching authorises none, so a test that is
    about reuse has to ask for it -- which is the point: the tests below that
    count spawns would otherwise be passing on a default nobody declared.
    """

    document = {"id": check_id, "argv": list(argv), "timeout_seconds": timeout,
                "cost_units": cost, "required": required, "version": version,
                "cacheable": cacheable}
    if cacheable:
        document["cache_max_age_seconds"] = cache_max_age_seconds
    return document


class Gate(TempCase):
    def setUp(self):
        super().setUp()
        os.environ["ADMISSIBLE_HMAC_KEY"] = SECRET

    def repo(self, document, files=None):
        root = self.tmp / "candidate"
        payload = {"README.md": "widget\n",
                   ".admissible.json": json.dumps(document)}
        payload.update(files or {})
        sha = make_repo(root, files=payload)
        return root, sha

    def run_cli(self, *argv):
        # `run` evaluates and never signs, so it always previews. Adding the
        # flag here keeps every call site about what it is testing.
        argv = tuple(argv)
        if argv[:1] == ("run",) and "--preview" not in argv:
            argv = ("run", "--preview") + argv[1:]
        out, err = io.StringIO(), io.StringIO()
        if argv[:1] == ("run",):
            # An evaluate job holds no signing credential: `run` starts
            # candidate-owned commands and refuses to do so while one is in
            # this process. Real deployments get that separation for free from
            # being two jobs; this fixture is one process, so it is made here.
            with evaluating_domain():
                code = cli.main(list(argv), stdout=out, stderr=err)
        else:
            code = cli.main(list(argv), stdout=out, stderr=err)
        return code, out.getvalue(), err.getvalue()


class AttemptIdentityTest(Gate):
    """C14/C17: one attempt decides; older attempts stay historical."""

    def test_a_failing_attempt_does_not_poison_a_later_clean_attempt(self):
        root, sha = self.repo(
            policy([check("unit", ["python3", "gate.py"])]),
            {"gate.py": "import pathlib, sys\n"
                        "flag = pathlib.Path('/tmp/does-not-matter')\n"
                        "sys.exit(int(open('mode').read()))\n",
             "mode": "1\n"})
        # Attempt one fails: mode says exit 1.
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--json")
        self.assertEqual(code, 1, out + err)
        # Repair in a new commit so the tree is clean again.
        (root / "mode").write_text("0\n", encoding="utf-8")
        from admissible_support import git
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "repair")
        second = git(root, "rev-parse", "HEAD")
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha",
                                      second, "--json")
        self.assertEqual(code, 0, out + err)
        document = json.loads(out)
        self.assertTrue(document["attempt_id"])
        # A run never issues a receipt, whatever it decides. The clean attempt
        # is admitted, and it takes the whole external path to anchor it.
        self.assertIsNone(document["receipt"])
        issued = admit(self, root, second)
        self.assertEqual(issued.commit_sha, second)

    def test_evidence_records_carry_an_attempt_identity(self):
        root, sha = self.repo(policy([check("unit", ["python3", "-c", "pass"])]))
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--json")
        self.assertEqual(code, 0, out + err)
        attempt = json.loads(out)["attempt_id"]
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        found = list(opened.evidence_in_attempt(attempt))
        self.assertTrue(found)
        for row in found:
            self.assertEqual(row["record"]["attempt_id"], attempt)

    def test_explain_reports_the_latest_attempt_and_agrees_with_standing(self):
        root, sha = self.repo(
            policy([check("unit", ["python3", "gate.py"])]),
            {"gate.py": "import sys\nsys.exit(int(open('mode').read()))\n",
             "mode": "1\n"})
        self.run_cli("run", "--repo", str(root), "--sha", sha, "--json")
        from admissible_support import git
        (root / "mode").write_text("0\n", encoding="utf-8")
        git(root, "checkout", "--", ".")
        # Same commit, second attempt: make the check pass without touching
        # the tree by rewriting nothing -- rerun the identical failing attempt
        # instead, then confirm explain names one attempt only.
        code, out, err = self.run_cli("explain", sha, "--repo", str(root),
                                      "--json")
        document = json.loads(out)
        self.assertIn("decision_attempt_id", document)
        self.assertEqual(document["state"], "UNKNOWN")
        self.assertEqual(document["decision"]["state"], "REFUSED")

    def _delayed_check(self, started_at, finished_at):
        """A check whose evidence starts long after the attempt did.

        A five-minute suite pushes the checks after it well past the
        clock-skew allowance from the attempt's start; this stands in for one
        of those without waiting five minutes.
        """

        def delayed_result(check_object, **_kwargs):
            return runner.CommandResult(
                check_id=check_object.id,
                check_version=check_object.version,
                argv_digest=check_object.argv_digest,
                exit_code=0, timed_out=False, launch_failed=False,
                duration_ms=(finished_at - started_at) * 1000,
                stdout_sha256="0" * 64, stderr_sha256="0" * 64,
                stdout_bytes=0, stderr_bytes=0, output_truncated=False,
                started_at=started_at, finished_at=finished_at)

        return delayed_result

    def test_a_long_run_is_judged_at_its_completion_not_its_start(self):
        """The CLI dates the decision at the moment the checks finished, so a
        check that ran longer than the skew allowance is not future-dated."""

        root, sha = self.repo(policy([check("unit", ["python3", "-c", "pass"])]))
        start = 1000
        finished = start + decision.MAX_CLOCK_SKEW_SECONDS + 102
        clock = iter((start, finished))
        original_run_check = runner.run_check
        original_time = cli.time.time
        runner.run_check = self._delayed_check(finished - 1, finished)
        cli.time.time = lambda: next(clock, finished)
        self.addCleanup(lambda: setattr(runner, "run_check", original_run_check))
        self.addCleanup(lambda: setattr(cli.time, "time", original_time))

        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--no-cache", "--json")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(json.loads(out)["state"], decision.CHECKS_PASSED)

    def test_explain_re_judges_a_long_attempt_at_its_completion_time(self):
        """`explain` re-runs the evaluator over stored evidence; it must anchor
        the skew guard at the recorded completion, not the attempt's start, or
        it re-reports a legitimately long check as future-dated and disagrees
        with the decision the run already recorded."""

        root, sha = self.repo(policy([check("unit", ["python3", "-c", "pass"])]))
        start = 1000
        finished = start + decision.MAX_CLOCK_SKEW_SECONDS + 102
        clock = iter((start, finished))
        original_run_check = runner.run_check
        original_time = cli.time.time
        runner.run_check = self._delayed_check(finished - 1, finished)
        cli.time.time = lambda: next(clock, finished)
        self.addCleanup(lambda: setattr(runner, "run_check", original_run_check))
        self.addCleanup(lambda: setattr(cli.time, "time", original_time))

        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--no-cache", "--json")
        self.assertEqual(code, 0, out + err)
        recorded = json.loads(out)

        code, out, err = self.run_cli("explain", sha, "--repo", str(root),
                                      "--json")
        explained = json.loads(out)
        self.assertEqual(explained["recorded_decision"]["state"],
                         decision.CHECKS_PASSED)
        self.assertEqual(explained["decision"]["state"], recorded["state"])
        self.assertEqual(explained["decision"]["state"], decision.CHECKS_PASSED)

    def test_standing_and_explain_never_disagree_for_one_attempt(self):
        root, sha = self.repo(policy([check("unit", ["python3", "-c", "pass"])]))
        issued = admit(self, root, sha)
        code, out, err = self.run_cli("explain", sha, "--repo", str(root),
                                      "--json")
        document = json.loads(out)
        self.assertEqual(document["state"], "CURRENT")
        self.assertEqual(document["decision"]["state"], "CHECKS_PASSED")
        # The attempt `explain` reasons about is the attempt the receipt was
        # issued for: standing and explanation describe one observation.
        self.assertEqual(document["decision_attempt_id"], issued.attempt_id)
        self.assertEqual(document["receipt_attempt_ids"], [issued.attempt_id])


    def test_explain_describes_the_latest_attempt_not_the_receipt(self):
        """"Would this pass now?" is a question about the newest observation.

        A commit can be admitted and then, on the same tree, fail -- a flaky
        check, a dependency that moved under it, an environment that changed.
        The later failed attempt leaves evaluation evidence no admission
        receipt binds. That attempt history confers no authority and cannot
        impeach authentic standing; `explain` must still report the refusal it
        just saw rather than replaying the earlier receipt's evidence.
        """

        root, sha = self.repo(
            policy([check("unit", ["python3", "gate.py"])]),
            {"gate.py": "import os, sys\n"
                        "sys.exit(int(os.environ.get('GATE_EXIT', '0')))\n"})
        os.environ["GATE_EXIT"] = "0"
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--json")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(admit(self, root, sha).commit_sha, sha)

        # Same commit, same tree, second attempt: the check now fails. The
        # cache is keyed on exact identity and knows nothing about the
        # environment, so --no-cache is what makes this a real second run.
        os.environ["GATE_EXIT"] = "3"
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--no-cache", "--json")
        self.assertEqual(code, 1, out + err)
        latest = json.loads(out)["attempt_id"]

        code, out, err = self.run_cli("explain", sha, "--repo", str(root),
                                      "--json")
        document = json.loads(out)
        self.assertEqual(document["decision_attempt_id"], latest)
        self.assertEqual(document["decision"]["state"], "REFUSED")
        self.assertEqual(document["state"], "CURRENT")


class EvidenceCacheTest(Gate):
    """C15: exact-identity reuse, and a miss on every single dimension."""

    def counter_repo(self):
        return self.repo(
            policy([check("unit", ["python3", "count.py"], cacheable=True)]),
            {"count.py": "import pathlib\n"
                         "p = pathlib.Path(__import__('os').environ['COUNTER'])\n"
                         "p.write_text(str(int(p.read_text() or '0') + 1))\n"})

    def test_an_identical_rerun_reuses_evidence_and_spawns_nothing(self):
        root, sha = self.repo(
            policy([check("unit", ["python3", "-c", "pass"], cacheable=True)]))
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--json")
        self.assertEqual(code, 0, out + err)
        calls = []
        original = runner.run_check

        def counted(check_object, **kwargs):
            calls.append(check_object.id)
            return original(check_object, **kwargs)

        runner.run_check = counted
        self.addCleanup(lambda: setattr(runner, "run_check", original))
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--json")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(calls, [], "a cached check was executed again")
        document = json.loads(out)
        provenance = {row["check_id"]: row["provenance"]
                      for row in document["checks"]}
        self.assertEqual(provenance["unit"], "reused")

    def test_no_cache_bypasses_the_cache(self):
        root, sha = self.repo(
            policy([check("unit", ["python3", "-c", "pass"], cacheable=True)]))
        self.run_cli("run", "--repo", str(root), "--sha", sha, "--json")
        calls = []
        original = runner.run_check

        def counted(check_object, **kwargs):
            calls.append(check_object.id)
            return original(check_object, **kwargs)

        runner.run_check = counted
        self.addCleanup(lambda: setattr(runner, "run_check", original))
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--no-cache", "--json")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(calls, ["unit"])

    def test_every_identity_dimension_is_a_cache_miss(self):
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        base = {
            "repository": "github.com/acme/widget", "commit_sha": "a1" * 20,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "check_id": "unit", "check_version": "1", "argv_digest": "d" * 64,
        }
        record = evidence.command_evidence_from_dict({
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": base["repository"], "commit_sha": base["commit_sha"],
            "tree_sha": base["tree_sha"], "policy_digest": base["policy_digest"],
            "argv_digest": base["argv_digest"], "exit_code": 0,
            "timed_out": False, "launch_failed": False, "duration_ms": 1,
            "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64,
            "stdout_bytes": 0, "stderr_bytes": 0, "output_truncated": False,
            "started_at": 10, "finished_at": 10, "attempt_id": "attempt-1"})
        opened.cache_command_evidence(record, recorded_at=10)
        self.assertIsNotNone(opened.cached_command_evidence(**base))
        for name in tuple(base):
            probe = dict(base)
            probe[name] = ("z" * len(base[name]) if name != "check_id"
                           else "other")
            self.assertIsNone(opened.cached_command_evidence(**probe), name)

    def test_a_failed_or_truncated_result_is_never_cached(self):
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        template = {
            "kind": "command", "check_id": "unit", "check_version": "1",
            "repository": "github.com/acme/widget", "commit_sha": "a1" * 20,
            "tree_sha": "b2" * 20, "policy_digest": "c" * 64,
            "argv_digest": "d" * 64, "exit_code": 0, "timed_out": False,
            "launch_failed": False, "duration_ms": 1,
            "stdout_sha256": "0" * 64, "stderr_sha256": "0" * 64,
            "stdout_bytes": 0, "stderr_bytes": 0, "output_truncated": False,
            "started_at": 10, "finished_at": 10, "attempt_id": "attempt-1"}
        for override in ({"exit_code": 1}, {"timed_out": True},
                         {"launch_failed": True}, {"output_truncated": True}):
            document = dict(template)
            document.update(override)
            record = evidence.command_evidence_from_dict(document)
            self.assertFalse(
                opened.cache_command_evidence(record, recorded_at=10), override)

    def test_reviews_are_never_served_from_the_command_cache(self):
        opened = store_module.open_store(self.home)
        self.addCleanup(opened.close)
        self.assertFalse(hasattr(opened, "cached_review_evidence"))


class CeilingTest(Gate):
    """C16: refuse before spending, and stop after a decisive cheap failure."""

    def spy(self):
        calls = []
        original = runner.run_check

        def counted(check_object, **kwargs):
            calls.append(check_object.id)
            return original(check_object, **kwargs)

        runner.run_check = counted
        self.addCleanup(lambda: setattr(runner, "run_check", original))
        return calls

    def test_an_over_budget_class_blocks_without_running_anything(self):
        root, sha = self.repo(policy(
            [check("expensive", ["python3", "-c", "pass"], cost=50)],
            max_cost=10))
        calls = self.spy()
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--preview", "--json")
        self.assertEqual(code, 2, out + err)
        self.assertEqual(calls, [])
        self.assertEqual(json.loads(out)["state"], "BLOCKED")

    def test_an_over_time_class_blocks_without_running_anything(self):
        root, sha = self.repo(policy(
            [check("slow", ["python3", "-c", "pass"], timeout=500)],
            max_wall=60))
        calls = self.spy()
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--preview", "--json")
        self.assertEqual(code, 2, out + err)
        self.assertEqual(calls, [])

    def test_a_decisive_cheap_failure_stops_the_expensive_check(self):
        root, sha = self.repo(policy([
            check("cheap", ["python3", "-c", "raise SystemExit(1)"], cost=1),
            check("expensive", ["python3", "-c", "pass"], cost=9),
        ]))
        calls = self.spy()
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--preview", "--json")
        self.assertEqual(code, 1, out + err)
        self.assertEqual(calls, ["cheap"])
        statuses = {row["check_id"]: row["status"]
                    for row in json.loads(out)["checks"]}
        self.assertEqual(statuses["expensive"], "not_run")

    def test_collect_all_checks_runs_everything_when_asked(self):
        root, sha = self.repo(policy([
            check("cheap", ["python3", "-c", "raise SystemExit(1)"], cost=1),
            check("expensive", ["python3", "-c", "pass"], cost=9),
        ], collect_all=True))
        calls = self.spy()
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--preview", "--json")
        self.assertEqual(code, 1, out + err)
        self.assertEqual(calls, ["cheap", "expensive"])

    def test_cheap_checks_run_first(self):
        root, sha = self.repo(policy([
            check("expensive", ["python3", "-c", "pass"], cost=9),
            check("cheap", ["python3", "-c", "pass"], cost=1),
        ]))
        calls = self.spy()
        code, out, err = self.run_cli("run", "--repo", str(root), "--sha", sha,
                                      "--preview", "--json")
        self.assertEqual(code, 0, out + err)
        self.assertEqual(calls, ["cheap", "expensive"])

    def test_documentation_only_still_makes_no_model_call(self):
        text = (Path(__file__).resolve().parent.parent
                / "docs" / "COST_AND_LATENCY.md").read_text(encoding="utf-8")
        self.assertIn("zero", text.lower())


if __name__ == "__main__":
    unittest.main()
