"""Project/context-aware cockpit server — TDD RED first."""
from __future__ import annotations

import unittest
from pathlib import Path

from server.app import CockpitEngine


REPO = Path(__file__).resolve().parents[1]
PROJECT = {
    "id": "fcd-test",
    "name": "FCD Test",
    "local_path": str(REPO),
    "github": "prive-hn/admissible",
    "base_branch": "main",
}


class ProjectContextServerTests(unittest.TestCase):
    def test_no_project_state_disables_work_creation(self):
        engine = CockpitEngine(seed=False)
        state = engine.state()
        self.assertIsNone(state["currentProject"])
        self.assertEqual(state["workItems"], [])
        with self.assertRaises(ValueError):
            engine.create_work_item("Cannot start globally")

    def test_compile_contract_matches_the_terms_a_line_actually_opens_under(self):
        """The approved contract and the enforced contract must be the same object.

        A cockpit that previews locally-guessed terms and then opens under the
        policy's real ones would make the visible contract a lie.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        previewed = engine.compile_contract("Add a CSV export")
        opened = engine.create_work_item("Add a CSV export")["contract"]
        self.assertEqual(previewed, opened)
        policy = engine.enforcer.policy
        self.assertEqual(previewed["cls"], "feature")
        self.assertEqual(previewed["policyVersion"], policy.version)
        self.assertEqual(
            [(s["kind"], s["name"]) for s in previewed["requiredStages"]],
            list(policy.required["feature"]),
        )
        self.assertEqual(previewed["allowSet"], sorted(policy.allow["feature"]))

    def test_compile_contract_opens_nothing(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        engine.compile_contract("Add a CSV export")
        self.assertEqual(engine.state()["workItems"], [])
        with self.assertRaises(ValueError):
            engine.compile_contract("   ")

    def test_a_class_may_require_one_gate_and_still_accept(self):
        """A4 says Required(c) is finite and ordered — not that it needs two.

        Investigating a repository needs no coder and no reviewer. The promise
        is narrower (no dual control) but every other theorem still holds.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        contract = engine.compile_contract("investigate why the retry loop stalls", "investigate")
        self.assertEqual(contract["cls"], "investigate")
        self.assertEqual([(g["kind"], g["name"]) for g in contract["requiredStages"]],
                         [("write", "answer")])
        self.assertEqual(contract["allowSet"], ["analyst:answer"])

    def test_gate_kind_is_declared_not_derived_from_position(self):
        """Only a check gate excludes authors (A6/I6), so kind cannot be a
        function of list order."""
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        feature = engine.compile_contract("add a rate limit to the endpoint", "feature")
        kinds = [g["kind"] for g in feature["requiredStages"]]
        self.assertEqual(kinds, ["write", "check"])
        policy = engine.enforcer.policy
        # The check gate's effective allow set drops whoever authored the line.
        self.assertEqual(policy.pi_star("feature", "check", {"builder:implement"}),
                         {"reviewer:review"})

    def test_intake_proposes_a_class_and_never_decides_it(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        proposed = engine.compile_contract("investigate how the watchdog works")
        self.assertEqual(proposed["cls"], "investigate")
        self.assertEqual(proposed["classChosenBy"], "intake")
        # The operator's choice overrides the proposal outright.
        overridden = engine.compile_contract("investigate how the watchdog works", "feature")
        self.assertEqual(overridden["cls"], "feature")
        self.assertEqual(overridden["classChosenBy"], "operator")

    def test_an_unreadable_prompt_defaults_to_the_most_scrutiny(self):
        """Guessing toward fewer gates would silently buy less review."""
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        contract = engine.compile_contract("Untitled thing with no telling words")
        self.assertEqual(contract["classChosenBy"], "default")
        self.assertEqual(contract["cls"], "feature")
        self.assertEqual(len(contract["requiredStages"]), 2)

    def test_guarded_intake_refuses_rather_than_guessing(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        engine.settings["intakeMode"] = "guarded"
        with self.assertRaises(ValueError) as caught:
            engine.compile_contract("Untitled thing with no telling words")
        self.assertIn("intake refused", str(caught.exception))
        # Naming the class explicitly satisfies guarded intake.
        self.assertEqual(
            engine.compile_contract("Untitled thing", "investigate")["cls"], "investigate")

    def test_a_line_opens_under_the_class_the_operator_approved(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("look into the cache behaviour", cls="investigate")
        item = engine.enforcer.items[created["id"]]
        self.assertEqual(item.cls, "investigate")
        self.assertEqual([(s.kind, s.name) for s in item.stages], [("write", "answer")])

    def test_duplicate_gate_ids_are_refused_because_phi_is_keyed_by_specialist(self):
        """Two gates sharing an id collapse to one phi entry — a wrong bind
        with no error, which is the failure this machine exists to prevent."""
        engine = CockpitEngine(seed=False)
        clashing = {
            **PROJECT, "id": "clash",
            "models": [{"id": "m", "provider": "demo", "api_id": "builder"}],
            "agents": [{"id": "a", "default_model_id": "m"}],
            "gates": [
                {"id": "review", "agent_id": "a", "model_id": "m"},
                {"id": "review", "agent_id": "a", "model_id": "m"},
            ],
        }
        with self.assertRaises(ValueError) as caught:
            engine.load_project(clashing)
        self.assertIn("duplicate gate id", str(caught.exception))

    def test_load_project_exposes_separate_agents_models_and_gate_defaults(self):
        engine = CockpitEngine(seed=False)
        loaded = engine.load_project(PROJECT)
        self.assertTrue(loaded["verified"])
        state = engine.state()
        self.assertEqual(state["currentProject"]["id"], "fcd-test")
        self.assertEqual({m["id"] for m in state["models"]}, {"builder-model", "review-model"})
        self.assertEqual({a["id"] for a in state["agents"]}, {"builder", "reviewer", "analyst"})
        review = next(g for g in state["gatePolicies"] if g["id"] == "review")
        self.assertEqual(review["model_id"], "review-model")
        self.assertEqual(review["context_mode"], "fresh_blind")

    def test_project_can_define_its_own_agents_models_and_gate_defaults(self):
        engine = CockpitEngine(seed=False)
        custom = dict(PROJECT, id="custom", models=[
            {"id": "m-build", "revision": 1, "provider": "openai", "api_id": "gpt-build", "display": "Build", "context_profile": "128k", "reasoning": "high"},
            {"id": "m-review", "revision": 1, "provider": "anthropic", "api_id": "claude-review", "display": "Review", "context_profile": "1m", "reasoning": "high"},
        ], agents=[
            {"id": "maker", "revision": 1, "name": "Maker", "instructions": "Implement", "default_model_id": "m-build", "tools": ["read", "write"], "authority": ["implement"]},
            {"id": "critic", "revision": 1, "name": "Critic", "instructions": "Review", "default_model_id": "m-review", "tools": ["read"], "authority": ["review"]},
        ], gates=[
            {"id": "implement", "revision": 1, "name": "Implement", "agent_id": "maker", "executor_id": "demo", "model_id": "m-build", "context_mode": "project_shared", "continuity": "fresh"},
            {"id": "review", "revision": 1, "name": "Review", "agent_id": "critic", "executor_id": "demo", "model_id": "m-review", "context_mode": "fresh_blind", "continuity": "fresh"},
        ])
        engine.load_project(custom)
        state = engine.state()
        self.assertEqual([m["api_id"] for m in state["models"]], ["gpt-build", "claude-review"])
        self.assertEqual([a["id"] for a in state["agents"]], ["maker", "critic"])
        self.assertEqual(state["gatePolicies"][1]["model_id"], "m-review")
        self.assertFalse(any(m["readiness"]["ready"] for m in state["models"]))
        created = engine.create_work_item("Unavailable custom route")
        with self.assertRaises(ValueError):
            engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")
        self.assertIn(created["workItem"]["openQuestionId"], engine.questions)
        self.assertNotIn(created["id"], engine.enforcer.store)

    def test_disconnected_declared_executor_blocks_admit(self):
        engine = CockpitEngine(seed=False)
        custom = dict(PROJECT, id="missing-executor", models=[
            {"id": "m-build", "provider": "demo", "api_id": "builder"},
            {"id": "m-review", "provider": "demo", "api_id": "reviewer"},
        ], agents=[
            {"id": "builder", "default_model_id": "m-build"},
            {"id": "reviewer", "default_model_id": "m-review"},
        ], gates=[
            {"id": "implement", "agent_id": "builder", "executor_id": "not-connected", "model_id": "m-build", "context_mode": "project_shared"},
            {"id": "review", "agent_id": "reviewer", "executor_id": "not-connected", "model_id": "m-review", "context_mode": "fresh_blind"},
        ])
        engine.load_project(custom)
        created = engine.create_work_item("Disconnected executor")
        config = next(g for g in engine.state()["gateConfigs"] if g["work_item_id"] == created["id"] and g["gate_id"] == "implement")
        self.assertFalse(config["readiness"]["ready"])
        self.assertFalse(config["readiness"]["executor_connected"])
        with self.assertRaises(ValueError):
            engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")

    def test_work_question_resume_creates_locked_receipt_backed_attempt(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Build context panel")
        iid = created["id"]
        engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")
        state = engine.state()
        attempts = [a for a in state["envelopes"] if a["work_item_id"] == iid]
        self.assertEqual(len(attempts), 1)
        self.assertTrue(attempts[0]["locked"])
        self.assertEqual(attempts[0]["model_provider"], "demo")
        self.assertEqual(attempts[0]["model_api_id"], "builder")
        self.assertEqual(attempts[0]["receipt_status"], "valid")
        self.assertEqual(attempts[0]["context_mode"], "project_shared")

    def test_review_gate_uses_fresh_blind_and_exact_review_model(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Build then review")
        iid = created["id"]
        engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")
        engine.action(iid, f"{iid}.1", "/retry")
        state = engine.state()
        review = next(a for a in state["envelopes"] if a["work_item_id"] == iid and a["gate_id"] == "review")
        self.assertEqual(review["context_mode"], "fresh_blind")
        self.assertEqual(review["model_provider"], "demo")
        self.assertEqual(review["model_api_id"], "reviewer")
        self.assertEqual(review["receipt_status"], "valid")
        self.assertEqual(engine.context.project_head("fcd-test"), (2, 2))

    def test_project_switch_does_not_carry_work_items(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        engine.create_work_item("Only in project one")
        second = dict(PROJECT, id="fcd-second", name="Second")
        engine.load_project(second)
        self.assertEqual(engine.state()["workItems"], [])
        engine.select_project("fcd-test")
        self.assertEqual(len(engine.state()["workItems"]), 1)

    def test_pre_admit_gate_config_is_editable_and_post_admit_attempt_locked(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Configure gates")
        iid = created["id"]
        state = engine.state()
        pre = next(g for g in state["gateConfigs"] if g["work_item_id"] == iid and g["gate_id"] == "implement")
        self.assertTrue(pre["editable"])
        engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")
        state2 = engine.state()
        post = next(g for g in state2["gateConfigs"] if g["work_item_id"] == iid and g["gate_id"] == "implement")
        self.assertFalse(post["editable"])
        self.assertIsNotNone(post["attempt_id"])

    def test_pre_admit_gate_override_is_versioned_and_closed_attempt_remains_inspectable(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Choose exact model")
        iid = created["id"]
        configured = engine.configure_gate(iid, "implement", {"model_id": "review-model"})
        self.assertEqual(configured["model_id"], "review-model")
        engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")
        old = next(a for a in engine.state()["envelopes"] if a["work_item_id"] == iid)
        self.assertTrue(old["locked"])
        self.assertEqual(old["state"], "Closed")
        retried = engine.configure_gate(iid, "implement", {"model_id": "builder-model"})
        self.assertEqual(retried["override_revision"], 2)

    def test_fresh_blind_gate_rejects_continuity_override(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Independent review")
        with self.assertRaises(ValueError):
            engine.configure_gate(created["id"], "review", {"continuity": "executor_continue"})

    def test_signed_impact_review_binds_current_head(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        a = engine.create_work_item("Feature A")
        b = engine.create_work_item("Feature B")
        engine.answer_question(a["workItem"]["openQuestionId"], "Proceed")
        engine.action(a["id"], f"{a['id']}.1", "/retry")
        drift = next(d for d in engine.state()["contextAtlas"]["drift"] if d["work_item_id"] == b["id"])
        self.assertEqual(drift["status"], "needs_review")
        review = engine.review_impact(b["id"], "reachable", "continue_pinned", "owner")
        self.assertEqual(tuple(review["reviewed_head"]), engine.context.project_head("fcd-test"))
        drift2 = next(d for d in engine.state()["contextAtlas"]["drift"] if d["work_item_id"] == b["id"])
        self.assertEqual(drift2["status"], "reviewed")

    def test_refresh_decision_blocks_stale_final_gate_before_store(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        a = engine.create_work_item("Advance head")
        b = engine.create_work_item("Stale candidate")
        engine.answer_question(a["workItem"]["openQuestionId"], "Proceed")
        engine.action(a["id"], f"{a['id']}.1", "/retry")
        engine.answer_question(b["workItem"]["openQuestionId"], "Proceed")
        engine.review_impact(b["id"], "reachable", "refresh", "owner")
        with self.assertRaises(ValueError):
            engine.action(b["id"], f"{b['id']}.1", "/retry")
        self.assertNotIn(b["id"], engine.enforcer.store)

    def test_terminal_failed_line_is_not_reported_as_context_drift(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        failed = engine.create_work_item("Will fail")
        engine.configure_gate(failed["id"], "implement", {"model_id": "review-model"})
        engine.answer_question(failed["workItem"]["openQuestionId"], "Proceed")
        accepted = engine.create_work_item("Advance after failure")
        engine.answer_question(accepted["workItem"]["openQuestionId"], "Proceed")
        engine.action(accepted["id"], f"{accepted['id']}.1", "/retry")
        drift_ids = {d["work_item_id"] for d in engine.state()["contextAtlas"]["drift"]}
        self.assertNotIn(failed["id"], drift_ids)


if __name__ == "__main__":
    unittest.main()


class ClassCompilationTests(unittest.TestCase):
    """The declaration an operator writes must be the policy the machine runs.

    Both regressions below passed every existing test: the fixture supplies no
    gates, so the whole supplied-gate path — the one a real project takes — had
    no coverage, and the single shipped class happened to span every gate in
    declaration order, which hid a positional lookup.
    """

    CUSTOM = dict(
        PROJECT, id="classes", models=[
            {"id": "m-build", "provider": "demo", "api_id": "builder"},
            {"id": "m-review", "provider": "demo", "api_id": "reviewer"},
        ], agents=[
            {"id": "builder", "default_model_id": "m-build"},
            {"id": "reviewer", "default_model_id": "m-review"},
        ], gates=[
            {"id": "implement", "agent_id": "builder", "model_id": "m-build",
             "context_mode": "project_shared", "kind": "write"},
            {"id": "review", "agent_id": "reviewer", "model_id": "m-review",
             "context_mode": "fresh_blind", "kind": "check"},
        ])

    def test_declared_check_kind_reaches_the_policy(self):
        """A gate declared `check` must exclude the authors of the line (A6, I6).

        The loader dropped `kind` on the way in, so every declared check gate
        became a write gate: `authors` was never subtracted, and the builder
        could pass its own review and enter the store.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(self.CUSTOM)
        required = engine.enforcer.policy.required["feature"]
        self.assertEqual(required, [("write", "implement"), ("check", "review")])

        policy = engine.enforcer.policy
        author = "builder:implement"
        self.assertNotIn(author, policy.pi_star("feature", "check", {author}))
        self.assertIn(author, policy.pi_star("feature", "write", {author}))

    def test_a_class_binds_the_gate_its_stage_names(self):
        """`Required(c)` is the class's gate list, not a slice of the project's.

        The envelope was built from `project.gates[pointer]`, so a class that
        does not start at gate 0 ran under a different agent, model and context
        mode than it declared — and still passed, because the receipt matched
        the wrong envelope it was given.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Explain how the retry loop works",
                                          cls="investigate")
        iid = created["id"]
        self.assertEqual(created["contract"]["requiredStages"],
                         [{"kind": "write", "name": "answer"}])
        engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")

        envelope = next(a for a in engine.state()["envelopes"]
                        if a["work_item_id"] == iid)
        self.assertEqual(envelope["gate_id"], "answer")
        self.assertEqual(envelope["agent_id"], "analyst")
        self.assertEqual(envelope["model_api_id"], "reviewer")

        stage = engine.enforcer.items[iid].stages[0]
        self.assertEqual(stage.pc, "Passed")
        self.assertIsNone(stage.fault)
        self.assertIn(iid, engine.enforcer.store)

    def test_a_class_may_not_open_on_a_check_gate(self):
        """Nothing has authored the line yet, so the exclusion excludes nobody."""
        engine = CockpitEngine(seed=False)
        bad = dict(self.CUSTOM, id="check-first", classes=[
            {"id": "backwards", "name": "Backwards", "gate_ids": ["review", "implement"]},
        ])
        with self.assertRaises(ValueError) as raised:
            engine.load_project(bad)
        self.assertIn("check gate", str(raised.exception))

    def test_a_class_needs_a_write_gate_and_may_not_repeat_one(self):
        engine = CockpitEngine(seed=False)
        with self.assertRaises(ValueError):
            engine.load_project(dict(self.CUSTOM, id="no-write", classes=[
                {"id": "review-only", "name": "Review only", "gate_ids": ["review"]},
            ]))
        with self.assertRaises(ValueError):
            engine.load_project(dict(self.CUSTOM, id="repeat", classes=[
                {"id": "twice", "name": "Twice", "gate_ids": ["implement", "implement"]},
            ]))

    def test_the_default_class_is_the_one_that_reviews_most(self):
        """A default must never be the cheap option: the class is fixed at Open.

        Ranking by gate count picked a three-write-gate class over a
        write-then-check class — more stages, no review at all.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(dict(self.CUSTOM, id="ranked", gates=[
            {"id": "implement", "agent_id": "builder", "model_id": "m-build", "kind": "write"},
            {"id": "review", "agent_id": "reviewer", "model_id": "m-review",
             "context_mode": "fresh_blind", "kind": "check"},
            {"id": "sketch", "agent_id": "builder", "model_id": "m-build", "kind": "write"},
            {"id": "draft", "agent_id": "builder", "model_id": "m-build", "kind": "write"},
        ], classes=[
            {"id": "triage", "name": "Triage", "gate_ids": ["implement", "sketch", "draft"],
             "hints": ["triage"]},
            {"id": "feature", "name": "Feature", "gate_ids": ["implement", "review"],
             "hints": ["feature"]},
        ]))
        contract = engine.compile_contract("something entirely unrelated")
        self.assertEqual(contract["cls"], "feature")
        self.assertEqual(contract["classChosenBy"], "default")
        self.assertIn("independent check", contract["classNote"])

    def test_a_hint_matches_a_word_not_a_substring(self):
        """"address" contains "add", which bought the one-gate class."""
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        self.assertEqual(
            engine.compile_contract("Address the prefix handling")["classChosenBy"],
            "default")
        self.assertEqual(
            engine.compile_contract("Add a CSV export")["cls"], "feature")


class AuthorityLivenessTests(unittest.TestCase):
    """The board must stay readable and must never run a gate it did not name."""

    def test_a_gate_runs_only_when_the_operator_named_it(self):
        """`/run` carried the tray's stage id and the dispatcher discarded it.

        The tray is rendered per selected stage, so asking to run a downstream
        gate ran the current one instead and reported it as the gate asked for.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Build then review", cls="feature")
        iid = created["id"]
        engine.answer_question(created["workItem"]["openQuestionId"], "Proceed")
        item = engine.enforcer.items[iid]
        self.assertEqual(item.pointer, 1)

        with self.assertRaises(ValueError) as raised:
            engine.action(iid, f"{iid}.0", "/run")
        self.assertIn("'review'", str(raised.exception))
        self.assertEqual(engine.enforcer.items[iid].pointer, 1)

        with self.assertRaises(ValueError):
            engine.action(iid, f"{iid}.7", "/run")
        with self.assertRaises(ValueError):
            engine.action(iid, "not-a-node", "/run")

    def test_running_a_gate_before_answering_the_question_is_refused(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Build a thing", cls="feature")
        iid = created["id"]
        with self.assertRaises(ValueError) as raised:
            engine.action(iid, f"{iid}.0", "/run")
        self.assertIn("question", str(raised.exception))
        self.assertEqual(engine.enforcer.items[iid].stages[0].pc, "Open")

    def test_the_board_stays_readable_while_the_executor_runs(self):
        """A dead authority that looks healthy is the one failure to avoid.

        Every engine entry point is serialized, and the executor call was
        inside that — so with a real adapter the whole board froze for the
        length of the run, at exactly the moment it should say the executor
        is producing evidence.
        """
        import threading

        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        created = engine.create_work_item("Build a thing", cls="feature")
        qid = created["workItem"]["openQuestionId"]

        entered, release = threading.Event(), threading.Event()
        inner = engine.execution.run

        def slow(request):
            entered.set()
            self.assertTrue(release.wait(5), "state() never returned mid-run")
            return inner(request)

        engine.execution.run = slow
        worker = threading.Thread(target=engine.answer_question, args=(qid, "Proceed"))
        worker.start()
        try:
            self.assertTrue(entered.wait(5), "executor never started")
            snapshot = engine.state()  # must not block on the running gate
            self.assertIsNotNone(snapshot["currentProject"])
        finally:
            release.set()
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(engine.enforcer.items[created["id"]].stages[0].pc, "Passed")


class SnapshotFreshnessTests(unittest.TestCase):
    def test_switching_projects_changes_the_revision(self):
        """A second tab has no refresh of its own; the stream is all it has.

        The counter was per project and started at zero for each, and neither
        select nor load bumped it — so switching between two projects at the
        same number emitted no frame, and a watching tab kept rendering the
        previous project under a Live badge.
        """
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        engine.create_work_item("First project line", cls="feature")
        second = dict(PROJECT, id="fcd-second", name="Second")
        engine.load_project(second)

        seen = engine.state()["revision"]
        engine.select_project("fcd-test")
        back = engine.state()
        self.assertNotEqual(back["revision"], seen)
        self.assertEqual(back["currentProject"]["id"], "fcd-test")
        self.assertEqual([w["id"] for w in back["workItems"]],
                         [w["id"] for w in back["workItems"]])

        forward = engine.state()["revision"]
        engine.select_project("fcd-second")
        self.assertNotEqual(engine.state()["revision"], forward)
        self.assertEqual(engine.state()["workItems"], [])

    def test_reloading_a_project_id_from_another_path_is_refused(self):
        """Project ids come from a directory basename, so two repositories of
        the same name under different roots collide. Swapping silently left the
        rail showing one repository and the policy pinned to another."""
        import subprocess, tempfile

        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        with tempfile.TemporaryDirectory() as tmp:
            run = lambda *a: subprocess.run(a, cwd=tmp, capture_output=True, check=True)
            run("git", "init", "-q", "-b", "main")
            run("git", "remote", "add", "origin",
                "https://github.com/prive-hn/admissible.git")
            run("git", "-c", "user.email=t@e", "-c", "user.name=t",
                "commit", "-q", "--allow-empty", "-m", "seed")
            with self.assertRaises(ValueError) as raised:
                engine.load_project(dict(PROJECT, local_path=tmp))
        self.assertIn("already loaded", str(raised.exception))

    def test_a_project_declaring_no_classes_still_compiles(self):
        """`"classes": []` used to build the policy from the submitted object
        while the registry derived a class into its own copy, so the UI listed
        a class every intake then died on."""
        engine = CockpitEngine(seed=False)
        engine.load_project(dict(PROJECT, id="empty-classes", classes=[]))
        contract = engine.compile_contract("Anything at all")
        self.assertIn(contract["cls"], {c["id"] for c in contract["classes"]})
        self.assertTrue(contract["requiredStages"])


class IntakeModeTests(unittest.TestCase):
    """A setting the authority cannot read is not a setting."""

    def test_explicit_class_requires_the_operator_to_name_it(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        engine.update_settings({"intakeMode": "explicit-class"})
        with self.assertRaises(ValueError) as raised:
            engine.compile_contract("Add a CSV export")
        self.assertIn("name the class", str(raised.exception))
        self.assertEqual(engine.compile_contract("Add a CSV export", "feature")["cls"],
                         "feature")

    def test_guarded_refuses_an_ambiguous_prompt_and_allows_a_clear_one(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        engine.update_settings({"intakeMode": "guarded"})
        with self.assertRaises(ValueError) as raised:
            engine.compile_contract("Investigate and fix the retry loop")
        self.assertIn("intake refused", str(raised.exception))
        self.assertEqual(engine.compile_contract("Add a CSV export")["cls"], "feature")

    def test_settings_refuse_unknown_keys_and_values(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        with self.assertRaises(ValueError):
            engine.update_settings({"intakeMode": "whatever"})
        with self.assertRaises(ValueError):
            engine.update_settings({"skin": "nocturne"})
        self.assertEqual(engine.state()["settings"]["intakeMode"], "class-inferred")


class SettingsSurfaceTests(unittest.TestCase):
    def test_every_mode_the_panel_offers_is_accepted(self):
        """The panel and the authority must agree on the option sets.

        Duplicating them is deliberate — the server must not accept a value
        just because a client sent it — but a set that drifts means the panel
        offers choices that are refused on save.
        """
        modal = (REPO / "apps/cockpit/src/components/SettingsModal.tsx").read_text()
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        for key, offered in (
            ("acceptanceMode", CockpitEngine.ACCEPTANCE_MODES),
            ("intakeMode", CockpitEngine.INTAKE_MODES),
            ("repairMode", CockpitEngine.REPAIR_MODES),
        ):
            for value in offered:
                self.assertIn(f'value: "{value}"', modal,
                              f"{key}={value} is accepted but never offered")
                engine.update_settings({key: value})
                self.assertEqual(engine.state()["settings"][key], value)
        # And nothing the panel offers is missing from the authority's sets.
        import re
        offered_all = set(re.findall(r'\{ value: "([a-z-]+)", note:', modal))
        known = set(CockpitEngine.ACCEPTANCE_MODES) | set(CockpitEngine.INTAKE_MODES) \
            | set(CockpitEngine.REPAIR_MODES)
        self.assertEqual(offered_all - known, set())


class AcceptedBytesBindingTests(unittest.TestCase):
    """The bytes stamped accepted are the bytes the reviewer's package hashed.

    Found by the RGA premise round: a steer between the write and check
    stages made the demo adapter regenerate the artifact during the REVIEW
    run, and the store then served bytes the reviewer never saw while every
    gate stayed green (paper/PROOFS.md, Body provenance)."""

    def _engine(self):
        engine = CockpitEngine(seed=False)
        engine.load_project(PROJECT)
        return engine

    def test_steered_review_cannot_replace_the_reviewed_candidate(self):
        engine = self._engine()
        item = engine.create_work_item("Ship the export")["workItem"]
        iid = item["id"]
        engine.answer_question(item["openQuestionId"], "CSV first")   # write stage runs
        candidate = engine.artifacts[iid]["srcDoc"]
        engine.steer(iid, f"{iid}.1", "Use a dark theme")             # steer the check stage
        engine.action(iid, f"{iid}.1", "/retry")                      # review runs, item accepts
        art = engine.artifacts[iid]
        self.assertEqual(art["state"], "accepted")
        self.assertEqual(art["srcDoc"], candidate)                    # reviewed bytes served
        self.assertNotIn("dark theme", art["srcDoc"])
        review = engine.meta[iid].get("review_artifacts", [])
        self.assertTrue(review and "dark theme" in review[-1]["srcDoc"])  # evidence kept, not served

    def test_single_write_stage_class_still_accepts_its_own_artifact(self):
        engine = self._engine()
        item = engine.create_work_item("Trace the retry path", cls="investigate")["workItem"]
        engine.answer_question(item["openQuestionId"], "Start at admit")
        art = engine.artifacts[item["id"]]
        self.assertEqual(art["state"], "accepted")                    # write-final class unaffected
