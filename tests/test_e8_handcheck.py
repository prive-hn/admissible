"""Fail-closed execution contract for the E8 hand adjudication."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "eval" / "realdefects" / "e8_handcheck.py"


def _load_handcheck():
    spec = importlib.util.spec_from_file_location("e8_handcheck_under_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    harness = types.ModuleType("e8_harness")
    setattr(harness, "load_pair", lambda _candidate: ({}, {}, None))
    setattr(harness, "observe", lambda _function, _args, _value: ("return", None))
    with mock.patch.dict("sys.modules", {"e8_harness": harness}):
        spec.loader.exec_module(module)
    return module


class HandcheckUsesRealStandardLibraryDependencies(unittest.TestCase):
    def test_scrapy_image_input_is_an_executable_hand_case(self):
        module = _load_handcheck()

        clickdata, form = module.HAND["scrapy/38"][0]

        self.assertIsNone(clickdata)
        image_inputs = form.xpath("descendant::input[@type='image']")
        self.assertEqual(len(image_inputs), 1)
        self.assertEqual(image_inputs[0].get("name"), "go")
        self.assertNotIn("scrapy/38", module.ARGUED_ONLY)

    def test_youtube_entity_check_uses_real_chr_on_both_sides(self):
        module = _load_handcheck()
        buggy_globals: dict[str, object] = {}
        fixed_globals: dict[str, object] = {}
        exec("def candidate(value): return compat_chr(value)", buggy_globals)
        exec("def candidate(value): return compat_chr(value)", fixed_globals)
        functions = {
            "buggy": buggy_globals["candidate"],
            "fixed": fixed_globals["candidate"],
        }

        module.bind_real_dependencies("youtube-dl/28", functions)

        self.assertIs(buggy_globals["compat_chr"], chr)
        self.assertIs(fixed_globals["compat_chr"], chr)

    def test_youtube_filter_check_uses_real_str_type_on_both_sides(self):
        module = _load_handcheck()
        buggy_globals: dict[str, object] = {}
        fixed_globals: dict[str, object] = {}
        exec("def candidate(value): return isinstance(value, compat_str)", buggy_globals)
        exec("def candidate(value): return isinstance(value, compat_str)", fixed_globals)
        functions = {
            "buggy": buggy_globals["candidate"],
            "fixed": fixed_globals["candidate"],
        }

        module.bind_real_dependencies("youtube-dl/24", functions)

        self.assertIs(buggy_globals["compat_str"], str)
        self.assertIs(fixed_globals["compat_str"], str)


class HandcheckExecutionIsFailClosed(unittest.TestCase):
    def test_an_unexecuted_intended_case_makes_the_process_fail(self):
        module = _load_handcheck()
        key = "example/1"
        setattr(module, "CANDS", {key: {"symbol": "candidate", "path": "candidate.py"}})
        setattr(module, "HAND", {})
        setattr(module, "HAND_SEPARATED", {})
        setattr(module, "ARGUED_ONLY", {key: "dependency unavailable"})
        setattr(module, "NOT_ADJUDICABLE", {})

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = module.main()

        self.assertEqual(exit_code, 1)
        self.assertIn('"not_run": 1', stdout.getvalue())
        self.assertIn('"failed": 1', stdout.getvalue())

    def test_a_runnable_case_that_cannot_load_makes_the_process_fail(self):
        module = _load_handcheck()
        key = "example/1"
        setattr(module, "CANDS", {key: {"symbol": "candidate", "path": "candidate.py"}})
        setattr(module, "HAND", {key: [("input",)]})
        setattr(module, "HAND_SEPARATED", {})
        setattr(module, "ARGUED_ONLY", {})
        setattr(module, "NOT_ADJUDICABLE", {})
        setattr(module, "load_pair", lambda _candidate: ({}, {}, "module-exec-failed"))

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = module.main()

        self.assertEqual(exit_code, 1)
        self.assertIn("HANDCHECK_SUMMARY", stdout.getvalue())
        self.assertIn('"executed": 0', stdout.getvalue())
        self.assertIn('"failed": 1', stdout.getvalue())

    def test_a_claimed_separation_that_does_not_separate_makes_the_process_fail(self):
        module = _load_handcheck()
        key = "example/1"
        setattr(module, "CANDS", {key: {"symbol": "candidate", "path": "candidate.py"}})
        setattr(module, "HAND", {key: [("input",)]})
        setattr(module, "HAND_SEPARATED", {})
        setattr(module, "ARGUED_ONLY", {})
        setattr(module, "NOT_ADJUDICABLE", {})
        setattr(
            module,
            "load_pair",
            lambda _candidate: ({"buggy": object(), "fixed": object()}, {}, None),
        )
        setattr(
            module,
            "observe",
            lambda _function, _args, _value: ("return", "same"),
        )

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = module.main()

        self.assertEqual(exit_code, 1)
        self.assertIn('"executed": 1', stdout.getvalue())
        self.assertIn('"separated": 0', stdout.getvalue())
        self.assertIn('"failed": 1', stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
