"""Contract: built-in profiles, closed `.admissible.json`, policy identity."""
from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from admissible_support import TempCase, require_module  # noqa: E402

profiles = require_module("admissible.profiles")
config = require_module("admissible.config")

EXPECTED_PROFILES = (
    "python-library",
    "typescript-application",
    "rest-api",
    "database-migration",
    "authentication-change",
    "payment-change",
    "infrastructure-change",
    "documentation-only",
)


class ProfileCatalogTest(unittest.TestCase):
    def test_exactly_eight_named_conservative_profiles(self):
        self.assertEqual(tuple(sorted(profiles.PROFILE_NAMES)),
                         tuple(sorted(EXPECTED_PROFILES)))

    def test_every_profile_documents_title_and_summary(self):
        for name in EXPECTED_PROFILES:
            profile = profiles.get_profile(name)
            self.assertEqual(profile.name, name)
            self.assertTrue(profile.title.strip())
            self.assertTrue(profile.summary.strip())

    def test_profile_document_is_plain_json_and_detached(self):
        document = profiles.profile_document("python-library")
        self.assertIs(type(document), dict)
        json.dumps(document)
        document["version"] = 999
        self.assertNotEqual(profiles.profile_document("python-library")["version"], 999)

    def test_unknown_profile_is_refused(self):
        with self.assertRaises(profiles.UnknownProfile):
            profiles.get_profile("does-not-exist")

    def test_every_profile_parses_as_a_closed_config(self):
        for name in EXPECTED_PROFILES:
            parsed = config.parse_config(profiles.profile_document(name),
                                         allow_placeholders=True)
            self.assertTrue(parsed.classes)
            self.assertTrue(parsed.policy_digest)

    def test_profiles_declare_no_shell_metacharacter_commands(self):
        for name in EXPECTED_PROFILES:
            parsed = config.parse_config(profiles.profile_document(name),
                                         allow_placeholders=True)
            for artifact_class in parsed.classes:
                for check in artifact_class.checks:
                    self.assertIs(type(check.argv), tuple)
                    self.assertTrue(check.argv)
                    for word in check.argv:
                        self.assertIs(type(word), str)


class ClosedConfigTest(TempCase):
    def base_document(self) -> dict:
        return {
            "version": 1,
            "profile": "python-library",
            "classes": [{
                "id": "default",
                "checks": [{
                    "id": "unit",
                    "argv": ["python", "-c", "pass"],
                    "timeout_seconds": 60,
                    "cost_units": 1,
                    "required": True,
                    "version": "1",
                }],
                "required_independent_reviews": 0,
                "review_max_age_seconds": 86400,
                "max_cost_units": 10,
                "max_wall_seconds": 600,
            }],
        }

    def test_minimal_document_parses(self):
        parsed = config.parse_config(self.base_document())
        self.assertEqual(parsed.select_class(None).id, "default")
        self.assertEqual(parsed.select_class("default").checks[0].argv,
                         ("python", "-c", "pass"))

    def test_unknown_top_level_key_is_refused(self):
        document = self.base_document()
        document["surprise"] = 1
        with self.assertRaises(config.ConfigError):
            config.parse_config(document)

    def test_unknown_check_key_is_refused(self):
        document = self.base_document()
        document["classes"][0]["checks"][0]["shell"] = "rm -rf /"
        with self.assertRaises(config.ConfigError):
            config.parse_config(document)

    def test_bool_is_not_accepted_where_int_is_required(self):
        document = self.base_document()
        document["classes"][0]["checks"][0]["timeout_seconds"] = True
        with self.assertRaises(config.ConfigError):
            config.parse_config(document)

    def test_argv_must_be_a_list_of_strings(self):
        for bad in ("python -c pass", ["python", 1], [], None):
            document = self.base_document()
            document["classes"][0]["checks"][0]["argv"] = bad
            with self.assertRaises(config.ConfigError):
                config.parse_config(document)

    def test_duplicate_class_and_check_ids_are_refused(self):
        document = self.base_document()
        document["classes"].append(dict(document["classes"][0]))
        with self.assertRaises(config.ConfigError):
            config.parse_config(document)
        document = self.base_document()
        document["classes"][0]["checks"].append(
            dict(document["classes"][0]["checks"][0]))
        with self.assertRaises(config.ConfigError):
            config.parse_config(document)

    def test_unknown_class_selection_is_refused(self):
        parsed = config.parse_config(self.base_document())
        with self.assertRaises(config.ConfigError):
            parsed.select_class("nope")

    def test_negative_or_zero_timeout_is_refused(self):
        for bad in (0, -1):
            document = self.base_document()
            document["classes"][0]["checks"][0]["timeout_seconds"] = bad
            with self.assertRaises(config.ConfigError):
                config.parse_config(document)

    def test_policy_digest_is_stable_and_order_independent(self):
        first = config.parse_config(self.base_document()).policy_digest
        again = config.parse_config(self.base_document()).policy_digest
        self.assertEqual(first, again)
        self.assertEqual(len(first), 64)

    def test_policy_digest_changes_with_check_version(self):
        document = self.base_document()
        before = config.parse_config(document).policy_digest
        document["classes"][0]["checks"][0]["version"] = "2"
        self.assertNotEqual(before, config.parse_config(document).policy_digest)

    def test_policy_digest_changes_with_argv(self):
        document = self.base_document()
        before = config.parse_config(document).policy_digest
        document["classes"][0]["checks"][0]["argv"] = ["python", "-c", "print(1)"]
        self.assertNotEqual(before, config.parse_config(document).policy_digest)

    def test_class_policy_digest_is_per_class(self):
        document = self.base_document()
        second = json.loads(json.dumps(document["classes"][0]))
        second["id"] = "docs"
        document["classes"].append(second)
        parsed = config.parse_config(document)
        default_digest = parsed.select_class("default").policy_digest
        docs_digest = parsed.select_class("docs").policy_digest
        self.assertEqual(len(default_digest), 64)
        self.assertNotEqual(default_digest, docs_digest)
        self.assertNotEqual(default_digest, parsed.policy_digest)

    def test_non_object_document_is_refused(self):
        for bad in ([], "x", 3, None, True):
            with self.assertRaises(config.ConfigError):
                config.parse_config(bad)


class InitTest(TempCase):
    def test_init_writes_config_and_refuses_overwrite(self):
        root = self.tmp / "repo"
        root.mkdir()
        path = config.init_config(root, "python-library")
        self.assertTrue(path.is_file())
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["profile"], "python-library")
        with self.assertRaises(config.ConfigError):
            config.init_config(root, "documentation-only")
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8"))["profile"],
            "python-library")

    def test_init_force_overwrites(self):
        root = self.tmp / "repo"
        root.mkdir()
        config.init_config(root, "python-library")
        path = config.init_config(root, "documentation-only", force=True)
        self.assertEqual(
            json.loads(path.read_text(encoding="utf-8"))["profile"],
            "documentation-only")

    def test_load_config_reads_the_repository_file(self):
        root = self.tmp / "repo"
        root.mkdir()
        config.init_config(root, "python-library")
        parsed = config.load_config(root)
        self.assertEqual(parsed.profile, "python-library")

    def test_load_config_missing_file_is_refused(self):
        with self.assertRaises(config.ConfigError):
            config.load_config(self.tmp / "empty")

    def test_load_config_rejects_trailing_garbage(self):
        root = self.tmp / "repo"
        root.mkdir()
        (root / config.CONFIG_FILENAME).write_text("{} {}", encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            config.load_config(root)


if __name__ == "__main__":
    unittest.main()
