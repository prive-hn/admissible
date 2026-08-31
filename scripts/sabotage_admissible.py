"""Sabotage each trust boundary of the developer admission product in turn and
confirm the contract suite goes red.

A test that passes when the guard it is supposed to cover has been deleted is
not covering that guard. Run this after changing anything in ``admissible/``:

    python3 scripts/sabotage_admissible.py

Each case edits one production line, runs one suite, and restores the file
whatever happens. It exits non-zero if any sabotage goes undetected.

Restoration is the part that has to be right. A harness that leaves a live
``if False:`` behind has not tested a guard, it has deleted one -- and the next
green run would be a lie. So every target is captured before anything is
touched, restored from that capture by an exit hook and by handlers for the
signals a CI runner actually sends, and finally *verified* byte for byte before
this program is allowed to report success.

A second phase follows, and it works differently on purpose. The cases above
sabotage the *product's* trust boundaries, one line of one file at a time. The
separation phase sabotages the *architecture*: that Ready and Trust are two
distributions which cannot reach each other, that the umbrella routes without
guessing, and that one schema has one owner. Those properties live in
packaging metadata, in whole modules and in files that only exist inside a
built wheel, so a single-line edit in place is the wrong instrument -- and
editing the live tree to install a Trust module inside the Ready package is a
worse thing to have to undo than an ``if False:``.

So every separation mutant is applied to a complete disposable copy of this
checkout in a temporary directory, and the named test runs there -- behind this
platform's network boundary, with an environment built from an allowlist and a
home directory of its own, because a mutated build backend is arbitrary code
and this is a developer's machine. Nothing in the working tree is touched,
which is why that phase has nothing to restore.

A separation kill is also a narrower claim than a red suite. Each mutant
registers the exception, the message and the exact number of the failures it is
aimed at, and a run that goes red any other way -- a module that stopped
importing, a fixture that raised, an unrelated assertion, or the intended
failure with an unrelated one beside it -- is reported as an error. Nor is the
account of what happened taken from the process being tested: it runs with no
descriptor on this program's channel, no key and no path, while a sealed
observer outside the clone watches from the far side of that boundary and
signs what it saw. The registry of what is mutated, of which named test must
notice and of what that test must say, is
``tests/architecture/separation_guards``; ``SEP1``--``SEP12`` are its stable
invariant ids and this program prints a receipt per invariant.
"""
import atexit
import hashlib
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv/bin/python"
PYTHON = str(VENV if VENV.exists() else Path(sys.executable))
SUITE_TIMEOUT_SECONDS = 900

CASES = [
    ("ready.py preview checks cannot claim Ready",
     "admissible/ready.py",
     '        return "checks_complete", (',
     '        return "ready", (',
     "tests.test_admissible_ready.ReadyMappingTest."
     "test_passing_preview_is_checks_complete_not_ready"),
    ("ready.py unauthenticated standing cannot claim Ready",
     "admissible/ready.py",
     "    if reported_standing == standing_module.CURRENT:",
     "    if True:",
     "tests.test_admissible_ready_e2e"),
    ("ready.py authenticated Ready may consume the unsigned latest attempt",
     "admissible/ready.py",
     "        elif (reported_standing in (\n"
     "                standing_module.CURRENT, standing_module.IMPEACHED)\n"
     "                and standing.receipts):",
     "        if False:",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_standing_presents_only_its_exact_receipt_attempt"),
    ("ready.py authenticated impeachment may require an unsigned local attempt",
     "admissible/ready.py",
     "                standing_module.CURRENT, standing_module.IMPEACHED)",
     "                standing_module.CURRENT, standing_module.CURRENT)",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_impeachment_does_not_require_a_local_attempt_row"),
    ("ready.py authenticated integrity may fall back to unsigned preview",
     "admissible/ready.py",
     "        if (signer is not None\n"
     "                and (standing.integrity_problem\n"
     "                     or standing.historical_receipts)):",
     "        if False:",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_integrity_problem_never_falls_back_to_preview"),
    ("ready.py authenticated integrity may still query receipt fallback",
     "admissible/ready.py",
     "        if (not authenticated_problem\n"
     "                and reported_standing == standing_module.UNKNOWN",
     "        if (True\n"
     "                and reported_standing == standing_module.UNKNOWN",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_integrity_problem_never_falls_back_to_preview"),
    ("ready.py authenticated admission may label unavailable checks as not checked",
     "admissible/ready.py",
     '            "check_evidence": "unavailable",',
     '            "check_evidence": "available",',
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_standing_presents_only_its_exact_receipt_attempt"),
    ("ready.py completed check may drift from work package policy",
     "admissible/ready.py",
     "    if expected_policy_digest is not None and (",
     "    if False and (",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_work_package_identity_matches_latest_explicit_class_attempt"),
    ("ready.py work package may ignore the selected policy path",
     "admissible/ready.py",
     "    selected_config = config_path or CONFIG_FILENAME",
     "    selected_config = CONFIG_FILENAME",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_work_package_identity_matches_latest_explicit_class_attempt"),
    ("ready.py agent work package may grant signing authority",
     "admissible/ready.py",
     '                "sign", "finalize", "trust_policy", "revoke_policy",',
     '                "finalize", "trust_policy", "revoke_policy",',
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_agent_work_package_is_exact_and_cannot_grant_authority"),
    ("agent_mcp.py unknown check arguments accepted",
     "admissible/agent_mcp.py",
     "            if set(arguments) - allowed:",
     "            if False:",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_tool_arguments_are_closed_and_bounded"),
    ("agent_mcp.py check may omit work package binding",
     "admissible/agent_mcp.py",
     "            if not required.issubset(arguments):",
     "            if False:",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_tool_arguments_are_closed_and_bounded"),
    ("agent_mcp.py request-only notifications may execute",
     "admissible/agent_mcp.py",
     "        if not has_id:\n"
     "            # Request-only methods, including initialize and tools/call, must",
     "        if False:\n"
     "            # Request-only methods, including initialize and tools/call, must",
     "tests.test_admissible_ready.MCPContractTest."
     "test_request_only_notification_is_silent_and_never_executes"),
    ("agent_mcp.py malformed initialized notification may enter operating state",
     "admissible/agent_mcp.py",
     "            if params or not self._initialize_responded:",
     "            if not self._initialize_responded:",
     "tests.test_admissible_ready.MCPContractTest."
     "test_initialized_notification_must_not_be_a_request_or_carry_params"),
    ("agent_mcp.py omitted no-argument tool arguments rejected",
     "admissible/agent_mcp.py",
     '            arguments = params.get("arguments", {})',
     '            arguments = params.get("arguments")',
     "tests.test_admissible_ready.MCPContractTest."
     "test_no_argument_tool_call_may_omit_arguments"),
    ("agent_mcp.py Ready output schema is open and partial",
     "admissible/agent_mcp.py",
     "_READY_OUTPUT_SCHEMA: dict[str, Any] = schema_module.ready_schema()",
     "_READY_OUTPUT_SCHEMA: dict[str, Any] = {\"type\": \"object\"}",
     "tests.test_admissible_ready.MCPContractTest."
     "test_initialize_then_list_exposes_only_bounded_ready_tools"),
    ("identity.py Git children may inherit signing credentials",
     "admissible/identity.py",
     "        environment.pop(name, None)",
     "        environment.get(name)",
     "tests.test_admissible_ready.FriendlyCheckCLITest."
     "test_ready_status_git_children_never_inherit_signing_credentials"),
    ("agent_connection.py live session made world-readable",
     "admissible/agent_connection.py",
     "    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)",
     "    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)",
     "tests.test_admissible_ready.AgentConnectionTest."
     "test_live_session_registry_is_private_and_cleans_up"),
    ("agent_connection.py Codex TOML emits surrogate escapes",
     "admissible/agent_connection.py",
     "    encoded = json.dumps(value, ensure_ascii=False)",
     "    encoded = json.dumps(value, ensure_ascii=True)",
     "tests.test_admissible_ready.AgentConnectionTest."
     "test_codex_setup_is_valid_toml_with_astral_unicode"),
    ("ready.py authenticated defect without receipt may claim admission",
     "admissible/ready.py",
     "        elif (signer is not None\n"
     "                and reported_standing == standing_module.IMPEACHED\n"
     "                and not standing.receipts):",
     "        elif False:",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_defect_without_receipt_never_claims_admission"),
    ("ready.py unsigned nested identity drift is accepted",
     "admissible/ready.py",
     "    if not _unsigned_identities_match(found, attempt, decision):",
     "    if False:",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_unsigned_attempt_with_nested_identity_drift_is_refused"),
    ("ready.py authenticated inspection may skip closing identity recapture",
     "admissible/ready.py",
     "    if (closing.repository != found.repository\n"
     "            or closing.commit_sha != found.commit_sha\n"
     "            or closing.tree_sha != found.tree_sha\n"
     "            or bool(closing.dirty) != bool(found.dirty)):",
     "    if False:",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_head_change_during_authenticated_inspection_cannot_report_ready"),
    ("ready.py closing identity error still reports ready",
     "admissible/ready.py",
     "        closing = identity_module.repository_identity(repo, allow_dirty=True)\n"
     "    except identity_module.IdentityError:\n"
     "        document = from_problem(",
     "        closing = identity_module.repository_identity(repo, allow_dirty=True)\n"
     "    except identity_module.IdentityError:\n"
     "        closing = found\n"
     "    if False:\n"
     "        document = from_problem(",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_closing_identity_error_during_authenticated_inspection_cannot_report_ready"),
    ("standing.py store error falls back to unsigned preview",
     "admissible/standing.py",
     "    except store_module.StoreError as error:\n"
     "        detail = str(error) or \"authenticated journal could not be read\"\n"
     "        return Standing(",
     "    except store_module.StoreError as error:\n"
     "        projections, invalid = {}, frozenset({repository})\n"
     "    if False:\n"
     "        return Standing(",
     "tests.test_admissible_ready.ReadyInspectionTest."
     "test_authenticated_store_error_never_falls_back_to_preview"),
    ("agent_mcp.py stdio may iterate unbounded lines",
     "admissible/agent_mcp.py",
     "            frame = _read_frame(source)",
     "            frame = next(iter(source), None)",
     "tests.test_admissible_ready.MCPContractTest."
     "test_stdio_rejects_oversized_frames_before_unbounded_iteration"),
    ("agent_mcp.py live session published before initialized",
     "admissible/agent_mcp.py",
     "            if server._operating and session is None:",
     "            if session is None:",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_stdio_session_is_visible_only_after_initialized_notification"),
    ("agent_mcp.py forged work package may execute checks",
     "admissible/agent_mcp.py",
     "            if issued is None:",
     "            if False:",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_check_requires_the_exact_package_issued_on_this_connection"),
    ("agent_mcp.py spent work package may execute checks",
     "admissible/agent_mcp.py",
     '            if issued["spent"]:',
     "            if False:",
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_spent_package_cannot_be_rechecked"),
    ("ready_server.py cross-site state GET accepted before store init",
     "admissible/ready_server.py",
     "            if path == \"/api/v1/state\" and not self._same_site():",
     "            if False:",
     "tests.test_admissible_ready_server.ReadyServerTest."
     "test_cross_site_state_get_is_rejected_before_store_initialization"),
    ("agent_connection.py Codex TOML leaves DEL unescaped",
     "admissible/agent_connection.py",
     '    return encoded.replace("\\x7f", "\\\\u007f")',
     "    return encoded",
     "tests.test_admissible_ready.AgentConnectionTest."
     "test_codex_setup_escapes_toml_forbidden_del_in_repository_path"),
    ("agent_connection.py stale heartbeat remains live",
     "admissible/agent_connection.py",
     "            and 0 <= now - heartbeat_at <= _HEARTBEAT_MAX_AGE_SECONDS",
     "            and True",
     "tests.test_admissible_ready.AgentConnectionTest."
     "test_session_registry_rejects_stale_heartbeat_and_pid_reuse"),
    ("agent_connection.py pid reuse without process start identity remains live",
     "admissible/agent_connection.py",
     "            and document.get(\"process_started_at\") == _process_start_token(pid)",
     "            and True",
     "tests.test_admissible_ready.AgentConnectionTest."
     "test_session_registry_rejects_stale_heartbeat_and_pid_reuse"),
    ("cli.py MCP may inherit signing credentials",
     "admissible/cli.py",
     "    ambient = runner_module.ambient_signing_credentials()\n"
     "    if ambient:\n"
     "        stderr.write(\n"
     '            "Unable to connect agent: this process contains a signing "',
     "    ambient = ()\n"
     "    if ambient:\n"
     "        stderr.write(\n"
     '            "Unable to connect agent: this process contains a signing "',
     "tests.test_admissible_ready.MCPToolIntegrationTest."
     "test_mcp_cli_refuses_to_start_with_signing_credentials"),
    ("cli.py Ready UI may inherit signing credentials",
     "admissible/cli.py",
     "    ambient = runner_module.ambient_signing_credentials()\n"
     "    if ambient:\n"
     "        stderr.write(\n"
     '            "Unable to start Ready UI: this process contains a signing "',
     "    ambient = ()\n"
     "    if ambient:\n"
     "        stderr.write(\n"
     '            "Unable to start Ready UI: this process contains a signing "',
     "tests.test_admissible_ready_server.ReadyUISecurityTest."
     "test_ui_refuses_to_start_with_signing_credentials"),
    ("ready_server.py cross-origin writes accepted",
     "admissible/ready_server.py",
     "            if not self._same_site():",
     "            if False:",
     "tests.test_admissible_ready_server.ReadyServerTest."
     "test_post_boundaries_reject_cross_origin_and_unknown_fields"),
    ("ready_server.py attacker-controlled Host accepted as local authority",
     "admissible/ready_server.py",
     '            if hostname not in ("127.0.0.1", "localhost", "::1"):',
     "            if False:",
     "tests.test_admissible_ready_server.ReadyServerTest."
     "test_attacker_host_cannot_pass_origin_check_by_dns_rebinding"),
    ("ready-state schema allows terminal action omission before Ready",
     "protocol/ready-state.schema.json",
     '      "else": {\n'
     '        "properties": {"next_actions": {"minItems": 1}}\n'
     "      }",
     '      "else": {\n'
     '        "properties": {"next_actions": {"minItems": 0}}\n'
     "      }",
     "tests.test_admissible_ready.ReadyMappingTest."
     "test_non_ready_state_cannot_omit_its_next_action"),
    ("ready-state schema may relabel preview checks as Ready",
     "protocol/ready-state.schema.json",
     '        "properties": {"status": {"const": "ready"}},\n'
     '        "required": ["status"]\n'
     '      },\n'
     '      "then": {\n'
     '        "properties": {\n'
     '          "canonical": {\n'
     '            "properties": {\n'
     '              "state": {"const": "ADMITTED"},\n'
     '              "readiness": {"const": "READY_FOR_ATTESTATION"},\n'
     '              "standing": {"const": "CURRENT"},',
     '        "properties": {"status": {"const": "ready"}},\n'
     '        "required": ["status"]\n'
     '      },\n'
     '      "then": {\n'
     '        "properties": {\n'
     '          "canonical": {\n'
     '            "properties": {\n'
     '              "state": {"const": "CHECKS_PASSED"},\n'
     '              "readiness": {"const": "READY_FOR_ATTESTATION"},\n'
     '              "standing": {"const": "UNKNOWN"},',
     "tests.test_admissible_ready.ReadyMappingTest."
     "test_unsigned_preview_cannot_be_relabelled_ready"),
    ("ready-state schema may lower authenticated terminal status",
     "protocol/ready-state.schema.json",
     '      "then": {\n'
     '        "properties": {"status": {"const": "ready"}}\n'
     "      }",
     '      "then": {\n'
     '        "properties": {"status": {"const": "checks_complete"}}\n'
     "      }",
     "tests.test_admissible_ready.ReadyMappingTest."
     "test_authenticated_terminal_state_must_use_ready_status"),
    ("Ready UI computes journey completion from optional check totals",
     "admissible/ready_static/ready.js",
     '    const checksDone = ["waiting_for_review", "checks_complete", "ready"].includes(document.status);',
     "    const checksDone = false;",
     "tests.test_admissible_ready_server.ReadyUISecurityTest."
     "test_journey_completion_follows_ready_status_not_optional_failures"),
    ("Ready UI labels unavailable authenticated evidence as not checked",
     "admissible/ready_static/ready.js",
     '    const unavailable = advanced?.check_evidence === "unavailable";',
     '    const unavailable = advanced?.check_evidence === "available";',
     "tests.test_admissible_ready_server.ReadyUISecurityTest."
     "test_authenticated_ready_does_not_label_unavailable_evidence_not_checked"),
    ("store.py CAS predecessor check removed",
     "admissible/store.py",
     "            fcd_head.MonotoneHeadRegistry._validate_next(head_receipt, current)",
     "            pass",
     "tests.test_admissible_store"),
    ("decision.py evidence binding disabled",
     "admissible/decision.py",
     "    if record.repository != repository:",
     "    if False:",
     "tests.test_admissible_decision"),
    ("receipt.py body digest check removed",
     "admissible/receipt.py",
     "    if body_digest != receipt.body_digest:",
     "    if False:",
     "tests.test_admissible_receipt"),
    ("receipt.py event/head binding removed",
     "admissible/receipt.py",
     "    if event_digest not in receipt.head.extension_digests:",
     "    if False:",
     "tests.test_admissible_receipt"),
    ("runner.py secret and control-channel stripping removed",
     "admissible/runner.py",
     "        and _SECRET_ENVIRONMENT.search(name) is None}",
     "        }",
     "tests.test_admissible_authority"),
    ("identity.py dirty worktree allowed",
     "admissible/identity.py",
     "    if dirty and not allow_dirty:",
     "    if False:",
     "tests.test_admissible_identity"),
    ("identity.py partial sha accepted",
     "admissible/identity.py",
     "        if _FULL_SHA.fullmatch(expected_sha) is None:",
     "        if False:",
     "tests.test_admissible_identity"),
    ("identity.py sha type check removed",
     "admissible/identity.py",
     "        if type(expected_sha) is not str:",
     "        if False:",
     "tests.test_admissible_identity"),
    ("github.py binds the synthetic merge sha",
     "admissible/github.py",
     "        commit_sha = _full_sha(head.get(\"sha\"))",
     "        commit_sha = _full_sha(environment.get(\"GITHUB_SHA\"))",
     "tests.test_admissible_github"),
    ("github.py fork previews may be finalized",
     "admissible/github.py",
     '    if document["fork"] is not False:',
     "    if False:",
     "tests.test_admissible_github"),
    ("runner.py log path containment removed",
     "admissible/runner.py",
     "        path = resolve_within(log_dir, name)",
     "        path = log_dir / name",
     "tests.test_admissible_identity"),
    ("fsutil.py containment check removed",
     "admissible/fsutil.py",
     "    if resolved == root or root not in resolved.parents:",
     "    if False:",
     "tests.test_admissible_identity"),
    ("config.py unknown keys accepted",
     "admissible/config.py",
     "    if unknown:",
     "    if False:",
     "tests.test_admissible_config"),
    ("evidence.py closed record check removed",
     "admissible/evidence.py",
     "    if unknown:",
     "    if False:",
     "tests.test_admissible_decision"),
    ("standing.py defect ignored by standing",
     "admissible/standing.py",
     "    if defects:",
     "    if False:",
     "tests.test_admissible_standing"),
    ("decision.py duplicate records resolve to the last one",
     "admissible/decision.py",
     "        record = min(matches, key=_severity)",
     "        record = matches[-1]",
     "tests.test_admissible_decision"),
    ("cli.py evidence bundle may carry defects",
     "admissible/cli.py",
     "        if bundle.defects:",
     "        if False:",
     "tests.test_admissible_cli"),
    ("identity.py remote credentials kept in the namespace",
     "admissible/identity.py",
     '    if "@" in text.split("/", 1)[0]:',
     "    if False:",
     "tests.test_admissible_identity"),
    ("store.py imported receipts accepted unverified",
     "admissible/store.py",
     "                receiptdata.verify_receipt(receipt, verifier)",
     "                pass",
     "tests.test_admissible_receipt"),
    ("store.py imported evidence digest unchecked",
     "admissible/store.py",
     "            if evidence_module.evidence_digest(parsed) != row[\"digest\"]:",
     "            if False:",
     "tests.test_admissible_receipt"),
    ("store.py imported defect anchoring unchecked",
     "admissible/store.py",
     "            if digest not in anchored_defects:",
     "            if False:",
     "tests.test_admissible_receipt"),
    ("store.py anchored defects may be omitted from an import",
     "admissible/store.py",
     "        missing = sorted(anchored_defects - supplied_defects)",
     "        missing = []",
     "tests.test_admissible_durability"),
    ("store.py imported evidence needs no signed receipt",
     "admissible/store.py",
     '            if row["digest"] not in anchored_evidence:',
     "            if False:",
     "tests.test_admissible_durability"),
    ("store.py dependency edges not rebuilt on import",
     "admissible/store.py",
     "            for dependency_repository, dependency_sha in receipt.dependencies:",
     "            for dependency_repository, dependency_sha in ():",
     "tests.test_admissible_durability"),
    ("store.py same-head reimport skips authentication",
     "admissible/store.py",
     "        self._authenticate_export(journal_id, events, receipts, verifier)",
     "        pass",
     "tests.test_admissible_final_repair"),
    ("store.py durable home requirement removed",
     "admissible/store.py",
     "    if hosted and declared not in (\"1\", \"true\", \"yes\"):",
     "    if False:",
     "tests.test_admissible_ci_trust"),
    ("store.py ephemeral home accepted",
     "admissible/store.py",
     "    if ephemeral:",
     "    if False:",
     "tests.test_admissible_ci_trust"),
    ("store.py cached evidence reused without revalidation",
     "admissible/store.py",
     "        if (record.repository != repository or record.commit_sha != commit_sha",
     "        if False and (",
     "tests.test_admissible_attempts"),
    ("store.py failed results are cached",
     "admissible/store.py",
     "        if not record.passed:",
     "        if False:",
     "tests.test_admissible_attempts"),
    ("receipt.py idempotency check moved out of the transaction",
     "admissible/receipt.py",
     "               preflight=receipt_transaction_preflight)",
     "               preflight=None)",
     "tests.test_admissible_durability"),
    ("receipt.py conflicting receipt rows silently ignored",
     "admissible/store.py",
     '        verb = "INSERT OR IGNORE" if idempotent else "INSERT"\n        return (\n            f"{verb} INTO workflow_receipts(receipt_hash, body_digest, "',
     '        verb = "INSERT OR IGNORE"\n        return (\n            f"{verb} INTO workflow_receipts(receipt_hash, body_digest, "',
     "tests.test_admissible_durability"),
    ("receipt.py a refused decision may be issued",
     "admissible/receipt.py",
     "    if result.state != CHECKS_PASSED:",
     "    if False:",
     "tests.test_admissible_authority"),
    ("receipt.py receipt need not match its decision",
     "admissible/receipt.py",
     "    if mismatched:",
     "    if False:",
     "tests.test_admissible_authority"),
    ("decision.py argv digest not compared",
     "admissible/decision.py",
     "            if record.argv_digest != check.argv_digest:",
     "            if False:",
     "tests.test_admissible_authority"),
    ("decision.py future-dated evidence accepted",
     "admissible/decision.py",
     "            if record.started_at > now + MAX_CLOCK_SKEW_SECONDS:",
     "            if False:",
     "tests.test_admissible_decision"),
    ("decision.py future-dated reviews accepted",
     "admissible/decision.py",
     "        if record.issued_at > now + MAX_CLOCK_SKEW_SECONDS:",
     "        if False:",
     "tests.test_admissible_authority"),
    ("decision.py unpinned reviewer keys are counted",
     "admissible/decision.py",
     "        if pinned and key_id not in pinned:",
     "        if False:",
     "tests.test_admissible_authority"),
    ("decision.py author keys count as independent reviewers",
     "admissible/decision.py",
     "        if key_id in authors:",
     "        if False:",
     "tests.test_admissible_authority"),
    ("decision.py a review-requiring class needs no pinned keyring",
     "admissible/decision.py",
     "    if artifact_class.required_independent_reviews > 0 and not pinned:",
     "    if False:",
     "tests.test_admissible_decision"),
    ("review.py attestation signature unchecked",
     "admissible/review.py",
     "    if not hmac.compare_digest(expected, parsed[\"signature\"]):\n        raise ReviewError(\n            f\"review attestation signed by {key_id!r} is not authentic; it was \"",
     "    if False:\n        raise ReviewError(\n            f\"review attestation signed by {key_id!r} is not authentic; it was \"",
     "tests.test_admissible_authority"),
    ("review.py any key in the keyring authenticates any claim",
     "admissible/review.py",
     "    secret = keyring.get(key_id) if isinstance(keyring, Mapping) else None\n    if secret is None:\n        raise ReviewError(\n            f\"no reviewer key {key_id!r} in this keyring; a review can only \"",
     '    secret = keyring.get(key_id, b"anything")\n    if secret is None:\n        raise ReviewError(\n            f"no reviewer key {key_id!r} in this keyring; a review can only "',
     "tests.test_admissible_authority"),
    ("github.py finalize trusts the preview's tree",
     "admissible/github.py",
     "    if observed.tree_sha != tree_sha:",
     "    if False:",
     "tests.test_admissible_authority"),
    ("github.py finalize trusts the preview's repository",
     "admissible/github.py",
     "    if observed.repository != document[\"repository\"]:",
     "    if False:",
     "tests.test_admissible_final_repair.SpecificRefusalTest."
     "test_a_forged_repository_is_refused_by_the_trusted_checkout"),
    ("github.py finalize needs no trusted checkout",
     "admissible/github.py",
     "    if policy_root is None:\n        raise GitHubError(",
     "    if False:\n        raise GitHubError(",
     "tests.test_admissible_authority"),
    ("github.py a candidate may ship its own tool copy",
     "admissible/github.py",
     "        if shadow.exists():",
     "        if False:",
     "tests.test_admissible_ci_trust"),
    ("cli.py ceilings enforced only after spending",
     "admissible/cli.py",
     "    if ceiling_reasons:",
     "    if False:",
     "tests.test_admissible_attempts"),
    ("cli.py no stop after a decisive required failure",
     "admissible/cli.py",
     "                stop = True",
     "                stop = False",
     "tests.test_admissible_attempts"),
    ("cli.py post-check mutation ignored",
     "admissible/cli.py",
     "            problems = _mutation_report(found, after)",
     "            problems = ()",
     "tests.test_admissible_authority"),
    ("cli.py a check that moves HEAD is ignored",
     "admissible/cli.py",
     "    if after.commit_sha != before.commit_sha:",
     "    if False:",
     "tests.test_admissible_authority"),
    ("cli.py preview handover ceiling removed",
     "admissible/cli.py",
     "    if len(encoded) > github_module.MAX_PREVIEW_HANDOVER_BYTES:",
     "    if False:",
     "tests.test_admissible_ci_trust"),
    ("cli.py explain ignores attempt scope",
     "admissible/cli.py",
     "    if attempt is not None:",
     "    if False:",
     "tests.test_admissible_attempts"),
    ("runner.py output bound raised past the limit",
     "admissible/runner.py",
     "                    room = self._limit - len(self._kept)",
     "                    room = 1 << 40",
     "tests.test_admissible_quality"),
    ("store.py open stores are not tracked to closure",
     "admissible/store.py",
     "        _OPEN_STORES.discard(self)",
     "        pass",
     "tests.test_admissible_durability"),
    ("gate workflow skips a repository with no policy",
     ".github/workflows/admissible-gate.yml",
     '          if [ ! -f "$CONFIG_PATH" ]; then',
     '          if false; then',
     "tests.test_admissible_ci_trust"),
    ("review.py an unauthenticated attestation is treated as verified",
     "admissible/review.py",
     "        evidence_module.UnverifiedReview(",
     "        evidence_module.VerifiedReview(",
     "tests.test_admissible_review_handoff"),
    ("decision.py an unauthenticated review is filed as a verified one",
     "admissible/decision.py",
     "        elif type(item) is UnverifiedReview:\n            unverified.append(item)",
     "        elif False:\n            unverified.append(item)",
     "tests.test_admissible_review_handoff"),
    ("decision.py a failed check may still be AWAITING_REVIEW",
     "admissible/decision.py",
     "    if any(outcome.required and outcome.status != \"passed\"",
     "    if False and any(outcome.required and outcome.status != \"passed\"",
     "tests.test_admissible_review_handoff"),
    ("decision.py every refusal counts as pending review",
     "admissible/decision.py",
     "    if any(reason.code not in _REVIEW_PENDING_CODES",
     "    if False and any(reason.code not in _REVIEW_PENDING_CODES",
     "tests.test_admissible_review_handoff"),
    ("github.py finalize accepts any readiness",
     "admissible/github.py",
     "    if readiness not in _FINALIZABLE_READINESS:",
     "    if False:",
     "tests.test_admissible_review_handoff.EvaluateStillFailsTest."
     "test_finalize_refuses_a_preview_that_is_not_ready"),
    ("gate workflow reports a pending review as green",
     ".github/workflows/admissible-gate.yml",
     '          if [ "$READINESS" = "AWAITING_REVIEW" ]; then',
     "          if false; then",
     "tests.test_admissible_review_handoff"),
    ("gate workflow accepts a pin that disagrees with the program",
     ".github/workflows/admissible-gate.yml",
     '          if [ -z "$JOB_WORKFLOW_SHA" ] || [ "$JOB_WORKFLOW_SHA" != "$TOOL_SHA" ]; then',
     "          if false; then",
     "tests.test_admissible_final_repair"),
    ("store.py the gate may keep its store inside the candidate",
     "admissible/store.py",
     "    if _inside(home, str(root)):",
     "    if False:",
     "tests.test_admissible_quality"),
    ("store.py rollback import allowed",
     "admissible/store.py",
     "                if current.receipt_hash != final.receipt_hash \\",
     "                if False and current.receipt_hash != final.receipt_hash \\",
     "tests.test_admissible_receipt"),
    ("store.py append-only triggers dropped",
     "admissible/store.py",
     "CREATE TRIGGER IF NOT EXISTS evidence_no_update",
     "CREATE VIEW IF NOT EXISTS unused_evidence_no_update AS SELECT 1; -- ",
     "tests.test_admissible_store"),
    ("decision.py evidence from another attempt still counts",
     "admissible/decision.py",
     "        if not _in_attempt(record, attempt_id) or not record.attempt_id:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("evidence.py reuse forgets where the observation came from",
     "admissible/evidence.py",
     "    source = record.reused_from_attempt or record.attempt_id",
     '    source = ""',
     "tests.test_admissible_final_repair"),
    ("github.py finalize needs no evaluation attestation",
     "admissible/github.py",
     "    if attestation_path is None:",
     "    if False:",
     "tests.test_admissible_final_repair"),
    ("github.py the evaluation attestation is never authenticated",
     "admissible/github.py",
     "        verified = attestation_module.verify_evaluation(attestation, keyring)",
     "        verified = attestation_module.parse_evaluation(document)",
     "tests.test_admissible_final_repair"),
    ("github.py the evaluation attestation may name another artefact",
     "admissible/github.py",
     "        if observed != expected:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("github.py the observer may cover a different set of records",
     "admissible/github.py",
     "        if sorted(observed) != present:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("github.py finalize signs against an untrusted policy",
     "admissible/github.py",
     "    require_trusted_policy(store, repository=repository,\n                           class_id=document[\"class_id\"],",
     "    _unused = dict(store=store, repository=repository,\n                           class_id=document[\"class_id\"],",
     "tests.test_admissible_final_repair"),
    ("github.py a class with no trusted baseline is signed anyway",
     "admissible/github.py",
     "    if not trusted:\n        raise GitHubError(",
     "    if False:\n        raise GitHubError(",
     "tests.test_admissible_final_repair"),
    ("github.py a policy that enforces something else is accepted",
     "admissible/github.py",
     "    raise GitHubError(\n        f\"the policy for class {class_id!r} in {repository} enforces something \"",
     "    return artifact_class.policy_digest\n    raise GitHubError(\n        f\"the policy for class {class_id!r} in {repository} enforces something \"",
     "tests.test_admissible_final_repair"),
    ("github.py finalize re-reads the default policy, not the selected one",
     "admissible/github.py",
     "        parsed = load_config(policy_root, config_relative)",
     "        parsed = load_config(policy_root)",
     "tests.test_admissible_final_repair"),
    ("github.py a preview that names no attempt is signed",
     "admissible/github.py",
     "    if type(attempt_id) is not str or not attempt_id.strip():",
     "    if False:",
     "tests.test_admissible_final_repair"),
    ("config.py a high-risk profile may be weakened",
     "admissible/config.py",
     "        if artifact_class.required_independent_reviews < minimum_reviews:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("config.py a high-risk profile may drop a required check",
     "admissible/config.py",
     "        missing = sorted(required_checks - present)",
     "        missing = []",
     "tests.test_admissible_final_repair"),
    ("config.py a review-requiring class needs no key lists",
     "admissible/config.py",
     "        if not values:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("config.py reviewer and author keys may overlap",
     "admissible/config.py",
     "    if overlap:",
     "    if False:",
     "tests.test_admissible_final_repair"),
    ("config.py a generated placeholder counts as a configured key",
     "admissible/config.py",
     "        if placeholders and not allow_placeholders:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("config.py --config escapes the repository root",
     "admissible/config.py",
     "        return resolve_within(root, selected)",
     "        return (Path(root) / relative).resolve()",
     "tests.test_admissible_final_repair"),
    ("config.py init writes the policy before checking for collisions",
     "admissible/config.py",
     "    if collisions and not force:",
     "    if False:",
     "tests.test_admissible_ci_trust"),
    ("config.py --ci invents a tool sha when none is given",
     "admissible/config.py",
     "        if allow_placeholder:\n            return TOOL_SHA_PLACEHOLDER",
     "        return TOOL_SHA_PLACEHOLDER",
     "tests.test_admissible_final_repair"),
    ("runner.py the process group survives a finished check",
     "admissible/runner.py",
     "            _kill_process_group(group, process)\n            # Killing is not reaping.",
     "            pass\n            # Killing is not reaping.",
     "tests.test_admissible_final_repair"),
    ("runner.py the runner namespace reaches the candidate",
     "admissible/runner.py",
     "        if not name.startswith(_CONTROL_NAMESPACES)",
     "        if True",
     "tests.test_admissible_final_repair"),
    ("runner.py the environment is not part of a cache identity",
     "admissible/runner.py",
     '        "platform": platform.platform(),',
     '        "platform": "",',
     "tests.test_admissible_final_repair"),
    ("store.py a newer failure no longer invalidates a cached pass",
     "admissible/store.py",
     "        if invalidated is not None and invalidated >= (row[\"sequence\"] or 0):",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("store.py a cached pass never expires",
     "admissible/store.py",
     "        if max_age_seconds > 0:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("store.py an uncacheable check is cached anyway",
     "admissible/store.py",
     "        if record.output_truncated or not cacheable:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("store.py events trailing past the last signed head are imported",
     "admissible/store.py",
     "        if len(events) != final.event_count:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("store.py a signed admission event needs no receipt",
     "admissible/store.py",
     "        if missing_admissions:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("store.py a receipt's evidence need not travel with it",
     "admissible/store.py",
     "        if missing_evidence:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("store.py a multi-head import commits head by head",
     "admissible/store.py",
     "            return self.transact(replay)",
     "            return replay()",
     "tests.test_admissible_final_repair"),
    ("store.py export mixes concurrent journal generations",
     "admissible/store.py",
     "        return self.read_transaction(\n"
     "            lambda: self._export_journal(journal_id,\n"
     "                                         through_head=through_head))",
     "        return self._export_journal(\n"
     "            journal_id, through_head=through_head)",
     "tests.test_admissible_durable_core_security."
     "ImportMultiplicitySecurityTest."
     "test_export_snapshot_survives_a_writer_between_head_reads"),
    ("store.py export discovers repositories through receipts only",
     "admissible/store.py",
     "            | {event[\"repository\"] for event in events",
     "            | {event[\"repository\"] for event in ()",
     "tests.test_admissible_final_repair"),
    ("store.py nonapproving review receives authenticated attribution",
     "admissible/store.py",
     "            if (row is None or row[\"kind\"] != \"review\"\n"
     "                    or row[\"record\"].verdict != \"approve\"):",
     "            if row is None or row[\"kind\"] != \"review\":",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_legacy_nonapproving_attribution_invalidates_projection"),
    ("store.py receipt-bound evidence may be absent from standing",
     "admissible/store.py",
     "            if row is None or digest in evidence_rows:",
     "            if False:",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_missing_receipt_bound_evidence_invalidates_current_authority"),
    ("store.py unbound attempt evidence is promoted to standing authority",
     "admissible/store.py",
     "        for digest in sorted(bound_evidence):",
     "        for digest in sorted(\n"
     "                set(bound_evidence) | {\n"
     "                    row[\"digest\"] for row in self._connection.execute(\n"
     "                        \"SELECT digest FROM evidence WHERE repository=?\",\n"
     "                        (repository,)).fetchall()}):",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_unbound_evidence_row_confers_no_authority"),
    ("cli.py run signs in the process that ran the checks",
     "admissible/cli.py",
     "    if not options.preview:",
     "    if False:",
     "tests.test_admissible_cli"),
    ("cli.py reused evidence is not derived into this attempt",
     "admissible/cli.py",
     "                commands.append(evidence_module.reuse_in_attempt(\n                    cached, attempt_id=attempt_id))",
     "                commands.append(cached)",
     "tests.test_admissible_external_consumer"),
    ("cli.py a check may rewrite the gate that judges it",
     "admissible/cli.py",
     "        if tool_after != tool_before:",
     "        if False:",
     "tests.test_admissible_final_repair"),
    ("cli.py a --json caller gets prose for a usage error",
     "admissible/cli.py",
     '    json_requested = "--json" in arguments',
     "    json_requested = False",
     "tests.test_admissible_final_repair"),
    ("cli.py an evaluation records nothing durable",
     "admissible/cli.py",
     "                opened.record_attempt(\n                    attempt_id=attempt_id,",
     "                _unused = dict(\n                    attempt_id=attempt_id,",
     "tests.test_admissible_attempts"),
    ("cli.py the recorded attempt forgets its own decision",
     "admissible/cli.py",
     "                    decision=decision_to_dict(result),",
     "                    decision=None,",
     "tests.test_admissible_final_repair"),
    ("cli.py finalize hides an anchored admission behind an output failure",
     "admissible/cli.py",
     "                message = (\n                    f\"the admission for {issued.commit_sha} IS anchored as \"",
     "                return _fail(stream, f\"cannot write {options.out}\",\n                             json_mode=options.json)\n"
     "                message = (\n                    f\"the admission for {issued.commit_sha} IS anchored as \"",
     "tests.test_admissible_cli"),
    ("receipt.py the receipt forgets which key authenticated each review",
     "admissible/receipt.py",
     "    normalized_reviews = tuple(sorted(\n        (item[0], item[1]) for item in authenticated_reviews))",
     "    normalized_reviews = ()",
     "tests.test_admissible_review_handoff"),
    ("attestation.py any key in the keyring authenticates any observer",
     "admissible/attestation.py",
     "    secret = keyring.get(key_id) if isinstance(keyring, Mapping) else None",
     '    secret = keyring.get(key_id, b"anything") if isinstance(keyring, Mapping) else None',
     "tests.test_admissible_final_repair"),
    ("attestation.py the evaluation signature is never compared",
     "admissible/attestation.py",
     '    if not hmac.compare_digest(expected, parsed["signature"]):',
     "    if False:",
     "tests.test_admissible_final_repair"),
    ("attestation.py the observer signs whatever the preview claims",
     "admissible/attestation.py",
     '        "command_digests": [evidence_module.evidence_digest(record)\n                            for record in bundle.commands],',
     '        "command_digests": preview.get("command_digests", []),',
     "tests.test_admissible_final_repair"),

    # -- the last bounded repair -------------------------------------------
    ("attestation.py an attestation may be signed with no source receipt",
     "admissible/attestation.py",
     "    if source_receipt is None:\n        raise EvaluationError(",
     "    if False:\n        raise EvaluationError(",
     "tests.test_admissible_bounded_repair"),
    ("attestation.py the source receipt may be for another commit",
     "admissible/attestation.py",
     '    if receipt["commit_sha"] != preview["commit_sha"]:',
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("attestation.py the fork flag need not be a boolean",
     "admissible/attestation.py",
     "    if type(fork) is not bool:",
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("attestation.py a source receipt digest may be absent",
     "admissible/attestation.py",
     "    if stated is None:\n        if computed is None:",
     "    if stated is None:\n        if False:",
     "tests.test_admissible_bounded_repair"),
    ("github.py the signed fork flag is never compared",
     "admissible/github.py",
     '    if statement["fork"] is not document["fork"]:',
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("github.py the signed dependency edges are never compared",
     "admissible/github.py",
     '    if statement["dependencies"] != declared:',
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("github.py state, readiness and config path are never compared",
     "admissible/github.py",
     '            ("config path", statement["config_path"],\n'
     '             document["config_path"])):',
     '            ("config path", document["config_path"],\n'
     '             document["config_path"])):',
     "tests.test_admissible_bounded_repair.AttestationClosureTest."
     "test_a_signed_statement_for_another_config_path_is_refused"),
    ("github.py a source receipt for another commit is accepted",
     "admissible/github.py",
     '    if receipt["commit_sha"] != commit_sha:',
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("github.py a failed source receipt still completes an admission",
     "admissible/github.py",
     '    if source_receipt["conclusion"] not in acceptable:',
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("github.py an observation dated in the future is accepted",
     "admissible/github.py",
     "    if observed_at > now + MAX_CLOCK_SKEW_SECONDS:",
     "    if False:",
     "tests.test_admissible_bounded_repair.FinalizeIdempotencyTest."
     "test_an_observation_from_the_future_is_refused"),
    ("github.py an observation predating the evaluation is accepted",
     "admissible/github.py",
     '    if statement["issued_at"] > observed_at + MAX_CLOCK_SKEW_SECONDS:',
     "    if False:",
     "tests.test_admissible_bounded_repair"),
    ("github.py the receipt is dated at retry time, not at observation",
     "admissible/github.py",
     '    observed_at = verified_evaluation["evaluation"]["observed_at"]',
     "    observed_at = now",
     "tests.test_admissible_bounded_repair"),
    ("github.py an abstention is recorded as an approval",
     "admissible/github.py",
     '        for item in verified if item.record.verdict == "approve"))',
     "        for item in verified))",
     "tests.test_admissible_bounded_repair"),
    ("github.py authorship attestations are never authenticated",
     "admissible/github.py",
     "        authorships = review_module.verify_bundle_authorship(\n            bundle, reviewer_keyring)",
     "        authorships = ()",
     "tests.test_admissible_review_handoff"),
    ("decision.py a decision may belong to no attempt",
     "admissible/decision.py",
     "    if type(attempt_id) is not str or not attempt_id.strip():",
     "    if False:",
     "tests.test_admissible_final_repair"),
    ("decision.py an unclaimed authorship still admits a reviewed class",
     "admissible/decision.py",
     "        if not authenticated_authors:",
     "        if False:",
     "tests.test_admissible_bounded_repair"),
    ("decision.py an unpinned author key claims authorship",
     "admissible/decision.py",
     "            if item.key_id not in authors:",
     "            if False:",
     "tests.test_admissible_bounded_repair"),
    ("decision.py a passing evaluation calls itself ADMITTED",
     "admissible/decision.py",
     '    state = CHECKS_PASSED\n\n    if state == CHECKS_PASSED and not remediation:',
     '    state = ADMITTED\n\n    if state == ADMITTED and not remediation:',
     "tests.test_admissible_bounded_repair"),
    ("receipt.py a receipt may bind evidence nobody supplied",
     "admissible/receipt.py",
     "    _prove_evidence_set(evidence_digests, commands, reviews, authorships)",
     "    pass",
     "tests.test_admissible_bounded_repair"),
    ("store.py two signed events for one record import cleanly",
     "admissible/store.py",
     "            if repeated:",
     "            if False:",
     "tests.test_admissible_bounded_repair"),
    ("store.py a duplicate defect row is silently ignored",
     "admissible/store.py",
     '        verb = "INSERT OR IGNORE" if idempotent else "INSERT"\n        return (\n            f"{verb} INTO defects(defect_id, repository, commit_sha, "',
     '        verb = "INSERT OR IGNORE"\n        return (\n            f"{verb} INTO defects(defect_id, repository, commit_sha, "',
     "tests.test_admissible_bounded_repair"),
    ("standing.py an orphan defect row is treated as idempotent success",
     "admissible/standing.py",
     "        if event_count == 2 and has_row:\n            raise _AlreadyFiled",
     "        if has_row:\n            raise _AlreadyFiled",
     "tests.test_admissible_durable_core_security."
     "DefectCorrespondenceSecurityTest."
     "test_orphan_defect_row_is_not_an_idempotent_success"),
    ("store.py policy generation read escapes BEGIN IMMEDIATE",
     "admissible/store.py",
     "        try:\n"
     "            with self._atomic():\n"
     "                current = self._policy_generation_locked(repository, class_id)\n"
     "                revoked = self._revoked_policies_locked(",
     "        try:\n"
     "            with contextlib.nullcontext():\n"
     "                current = self._policy_generation_locked(repository, class_id)\n"
     "                revoked = self._revoked_policies_locked(",
     "tests.test_admissible_durable_core_security."
     "PolicyTransactionSecurityTest."
     "test_policy_generation_is_read_inside_the_write_transaction"),
    ("store.py re-trust collides with its revoked generation",
     "admissible/store.py",
     "                    if policy_digest in revoked or same_enforcement is None",
     "                    if same_enforcement is None",
     "tests.test_admissible_durable_core_security."
     "PolicyTransactionSecurityTest."
     "test_retrusting_a_revoked_policy_opens_a_new_generation"),
    ("store.py schema-v5 stranded policy table is ignored",
     "admissible/store.py",
     "    def _add_missing_columns(self) -> None:\n"
     '        """Widen tables an older home already created, never rebuild them."""\n'
     "\n"
     "        self._migrate_trusted_policies()",
     "    def _add_missing_columns(self) -> None:\n"
     '        """Widen tables an older home already created, never rebuild them."""\n'
     "\n"
     "        pass",
     "tests.test_admissible_durable_core_security."
     "PolicyTransactionSecurityTest."
     "test_schema_v5_recovers_legacy_after_rename_before_copy"),
    ("store.py stranded generation recovers two current enforcements",
     "admissible/store.py",
     "        if ambiguous_current is not None:\n"
     "            raise sqlite3.DatabaseError(\n"
     "                \"one trusted-policy generation contains distinct \"",
     "        if False:\n"
     "            raise sqlite3.DatabaseError(\n"
     "                \"one trusted-policy generation contains distinct \"",
     "tests.test_admissible_durable_core_security."
     "PolicyTransactionSecurityTest."
     "test_stranded_generation_cannot_recover_two_current_enforcements"),
    ("store.py conflicting stranded policy row is silently ignored",
     "admissible/store.py",
     "        if conflict is not None:\n"
     "            raise sqlite3.DatabaseError(\n"
     "                \"stranded and current trusted-policy rows conflict\")",
     "        if False:\n"
     "            raise sqlite3.DatabaseError(\n"
     "                \"stranded and current trusted-policy rows conflict\")",
     "tests.test_admissible_durable_core_security."
     "PolicyTransactionSecurityTest."
     "test_schema_v5_fails_closed_on_conflicting_legacy_and_new_rows"),
    ("store.py corrupt current policy generation returns two gates",
     "admissible/store.py",
     "                if len({row[\"enforcement_digest\"] for row in rows}) > 1:",
     "                if False:",
     "tests.test_admissible_durable_core_security."
     "PolicyTransactionSecurityTest."
     "test_corrupt_current_generation_never_returns_two_enforcements"),
    ("store.py cache sequence allocates outside a fact transaction",
     "admissible/store.py",
     "        if not self._connection.in_transaction:\n"
     "            raise StoreError(\n"
     "                \"a cache sequence may only be allocated inside the same \"",
     "        if False:\n"
     "            raise StoreError(\n"
     "                \"a cache sequence may only be allocated inside the same \"",
     "tests.test_admissible_durable_core_security."
     "CacheTransactionSecurityTest."
     "test_sequence_cannot_be_allocated_outside_its_fact_transaction"),
    ("store.py direct journal import ignores the 64 MiB ceiling",
     "admissible/store.py",
     "        if size > MAX_JOURNAL_BYTES:\n"
     "            raise StoreError(",
     "        if False:\n"
     "            raise StoreError(",
     "tests.test_admissible_durable_core_security."
     "ImportMultiplicitySecurityTest."
     "test_direct_import_honours_the_same_size_bound_as_the_cli"),
    ("store.py duplicate evidence attachment imports once",
     "admissible/store.py",
     "            if row[\"digest\"] in supplied_evidence:\n"
     "                raise StoreError(",
     "            if False:\n"
     "                raise StoreError(",
     "tests.test_admissible_durable_core_security."
     "ImportMultiplicitySecurityTest."
     "test_duplicate_bound_evidence_is_rejected"),
    ("store.py imported defect forgets its signed filing time",
     "admissible/store.py",
     "                filed_at=filed_at,\n"
     "                record=evidence_module.defect_to_dict(defect),",
     "                filed_at=defect.discovered_at,\n"
     "                record=evidence_module.defect_to_dict(defect),",
     "tests.test_admissible_durable_core_security."
     "ImportMultiplicitySecurityTest."
     "test_import_preserves_signed_defect_filing_time"),
    ("store.py imported dependency keeps conflicting unsigned metadata",
     "admissible/store.py",
     "            if stored is None or stored[\"recorded_at\"] != expected_at:\n"
     "                raise StoreError(",
     "            if False:\n"
     "                raise StoreError(",
     "tests.test_admissible_durable_core_security."
     "ImportMultiplicitySecurityTest."
     "test_import_rejects_conflicting_existing_dependency_metadata"),
    ("store.py standing accepts unsigned dependency attachment metadata",
     "admissible/store.py",
     "        if stored_dependency_times != expected_dependency_times:\n"
     "            raise StoreError(",
     "        if False:\n"
     "            raise StoreError(",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_unsigned_same_edge_blocks_signed_attachment_issuance"),
    ("store.py repeated signed dependency edge uses its latest timestamp",
     "admissible/store.py",
     "                expected_dependency_times[edge] = min(\n"
     "                    item.issued_at,\n"
     "                    expected_dependency_times.get(edge, item.issued_at))",
     "                expected_dependency_times[edge] = item.issued_at",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_repeated_signed_edge_uses_the_earliest_receipt_timestamp"),
    ("store.py standing skips workflow receipt authentication",
     "admissible/store.py",
     "                receiptdata.verify_receipt(item, verifier)\n"
     "            except (receiptdata.ReceiptError, ValueError) as error:",
     "                pass\n"
     "            except (receiptdata.ReceiptError, ValueError) as error:",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_tampered_workflow_receipt_cannot_inherit_an_authentic_head"),
    ("standing.py ADMITTED row is CURRENT without a verifier",
     "admissible/standing.py",
     "            state=UNKNOWN, repository=repository, commit_sha=commit_sha,\n"
     "            receipts=(), defects=(), unknown_scope=True,\n"
     "            unauthenticated=(), historical_receipts=(),\n"
     "            integrity_problem=\"a verifier is required for standing\")",
     "            state=CURRENT, repository=repository, commit_sha=commit_sha,\n"
     "            receipts=(), defects=(), unknown_scope=True,\n"
     "            unauthenticated=(), historical_receipts=(),\n"
     "            integrity_problem=\"\")",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_no_verifier_means_unknown_even_when_a_row_says_admitted"),
    ("store.py standing ignores a signed defect missing its attachment",
     "admissible/store.py",
     "        if supplied_defects != set(defect_events):\n"
     "            raise StoreError(",
     "        if False:\n"
     "            raise StoreError(",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_signed_defect_event_without_its_attachment_is_unknown"),
    ("store.py authenticated projection drops authorship evidence",
     "admissible/store.py",
     "                elif row[\"kind\"] == \"authorship\":\n"
     "                    parsed = evidence_module.authorship_evidence_from_dict(record)",
     "                elif row[\"kind\"] == \"authorship\":\n"
     "                    raise StoreError(\"authorship disabled\")",
     "tests.test_admissible_durable_core_security."
     "AuthenticatedStandingSecurityTest."
     "test_receipt_bound_authorship_is_reconstructed_as_authenticated_data"),
    ("fsutil.py init writes straight through a symbolic link",
     "admissible/fsutil.py",
     "        if current.is_symlink():",
     "        if False:",
     "tests.test_admissible_bounded_repair"),
    ("config.py init writes one target at a time again",
     "admissible/config.py",
     "    for item in writes:\n        _writable_target(item.path, item.relative)\n    return tuple(writes)",
     "    return tuple(writes)",
     "tests.test_admissible_bounded_repair"),
    ("config.py the enforcement digest forgets the ceilings and the timeouts",
     "admissible/config.py",
     '                 "timeout_seconds": check.timeout_seconds,\n                 "cost_units": check.cost_units,\n                 "cache_max_age_seconds": check.cache_max_age_seconds}',
     "                 }",
     "tests.test_admissible_bounded_repair"),
    ("config.py the enforcement digest forgets collect_all_checks",
     "admissible/config.py",
     '            "collect_all_checks": artifact_class.collect_all_checks,',
     "",
     "tests.test_admissible_bounded_repair"),
    ("runner.py the cache fingerprint ignores the child environment",
     "admissible/runner.py",
     '        "environment": dict(sorted(environment.items())),',
     "",
     "tests.test_admissible_bounded_repair"),
    ("runner.py the cache fingerprint ignores the resolved executables",
     "admissible/runner.py",
     '        "executables": sorted(\n            (_executable_identity(name, environment)\n             for name in sorted(set(executables))),\n            key=lambda item: item["name"]),',
     "",
     "tests.test_admissible_bounded_repair"),
    ("runner.py the cache fingerprint ignores the repository lockfiles",
     "admissible/runner.py",
     '        "lockfiles": _lockfile_digests(root),',
     "",
     "tests.test_admissible_bounded_repair"),
    ("cli.py an interrupted finalize claims nothing was committed",
     "admissible/cli.py",
     "        return _report_interrupted_finalize(\n"
     "            options, stdout, stream, opened, expected_body_digest)",
     "        raise",
     "tests.test_admissible_bounded_repair"),
    ("cli.py impeachment anchors on disposable storage",
     "admissible/cli.py",
     "        home = store_module.require_durable_home()\n        opened = store_module.open_store(home)\n    except (identity_module.IdentityError, ConfigError,",
     "        opened = _open_store(stream)\n    except (identity_module.IdentityError, ConfigError,",
     "tests.test_admissible_bounded_repair"),
    ("cli.py attest-evaluation no longer needs a source receipt",
     "admissible/cli.py",
     '        source = attestation_module.read_source_receipt_file(\n            options.source_receipt)',
     "        source = None",
     "tests.test_admissible_bounded_repair"),
    ("cli.py explain re-judges a commit no attempt ever observed",
     "admissible/cli.py",
     "        if not attempt_id:",
     "        if False:",
     "tests.test_admissible_cli"),
    ("workflow YAML reports AWAITING_REVIEW as a green gate",
     ".github/workflows/admissible-gate.yml",
     '          if [ "$READINESS" = "AWAITING_REVIEW" ]; then',
     "          if false; then",
     "tests.test_admissible_bounded_repair"),
    ("workflow YAML hands the scratch directory to candidate commands",
     ".github/workflows/admissible-gate.yml",
     "          ADMISSIBLE_SCRATCH: ${{ steps.scratch.outputs.dir }}",
     "          SCRATCH: ${{ steps.scratch.outputs.dir }}",
     "tests.test_admissible_bounded_repair"),

    # -- frozen evaluation/finalization core ------------------------------
    ("evaluation state enum guard removed",
     "admissible/attestation.py",
     "    if type(state) is not str or state not in EVALUATION_STATES:",
     "    if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_evaluation_state_enum_is_exact"),
    ("evaluation readiness enum guard removed",
     "admissible/attestation.py",
     "    if type(readiness) is not str or readiness not in READINESS:",
     "    if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_evaluation_readiness_enum_is_exact"),
    ("evaluation state readiness coherence guard removed",
     "admissible/attestation.py",
     "    if readiness not in coherent[state]:",
     "    if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_evaluation_state_readiness_pair_must_be_coherent"),
    ("observer signature drops preview schema binding",
     "admissible/attestation.py",
     '        "preview_schema": preview["schema"],\n',
     "",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_signed_statement_binds_preview_schema_and_issued_at"),
    ("finalizer drops observer signed issued_at comparison",
     "admissible/github.py",
     '            ("preview issued_at", statement["issued_at"],\n             document["issued_at"]),\n',
     "",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_preview_issued_at_cannot_change_after_observation"),
    ("observer isolation input falls back to candidate preview",
     "admissible/attestation.py",
     "    if isolation is None:\n        raise EvaluationError(\n            \"no observer isolation assertion. The preview's isolation field \"\n            \"is candidate-adjacent data and cannot assert the boundary that \"\n            \"made observation safe. Supply isolation explicitly from the \"\n            \"observer's trust domain. Nothing was signed.\")",
     '    if isolation is None:\n        isolation = preview["isolation"]',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_observer_isolation_is_a_required_independent_input"),
    ("observer signature copies candidate preview isolation",
     "admissible/attestation.py",
     '        "isolation": isolation,',
     '        "isolation": preview["isolation"],',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_candidate_none_does_not_override_observer_isolation"),
    ("finalizer accepts observer asserted isolation none",
     "admissible/github.py",
     "    if observer_isolation == ISOLATION_NONE:",
     "    if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_observer_none_is_nonfinalizable"),
    ("preview and embedded decision correspondence removed",
     "admissible/github.py",
     "        if document[preview_key] != decision_document[decision_key]:",
     "        if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_top_level_and_embedded_state_readiness_must_match"),
    ("trusted evaluator state readiness rederivation comparison removed",
     "admissible/github.py",
     '    if (document["state"] != evaluator_result.state\n            or document["readiness"] != evaluator_readiness):',
     "    if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_provider_matrix_uses_rederived_evaluator_readiness"),
    ("provider matrix consumes preview readiness",
     "admissible/github.py",
     "    acceptable = attestation_module.admissible_source_conclusions(\n        evaluator_readiness)",
     "    acceptable = attestation_module.admissible_source_conclusions(\n        document[\"readiness\"])",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_provider_matrix_follows_rederived_readiness_in_source_order"),
    ("READY provider conclusion accepts failure",
     "admissible/attestation.py",
     'ADMISSIBLE_SOURCE_CONCLUSIONS = frozenset({"success"})',
     'ADMISSIBLE_SOURCE_CONCLUSIONS = frozenset({"success", "failure"})',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_provider_conclusion_matrix_is_exact"),
    ("AWAITING provider conclusion rejects failure",
     "admissible/attestation.py",
     'AWAITING_REVIEW_SOURCE_CONCLUSIONS = frozenset({"success", "failure"})',
     'AWAITING_REVIEW_SOURCE_CONCLUSIONS = frozenset({"success"})',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_provider_conclusion_matrix_is_exact"),
    ("provider conclusion matrix accepts cancelled and timed_out",
     "admissible/attestation.py",
     'AWAITING_REVIEW_SOURCE_CONCLUSIONS = frozenset({"success", "failure"})',
     'AWAITING_REVIEW_SOURCE_CONCLUSIONS = frozenset({"success", "failure", "cancelled", "timed_out"})',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_provider_conclusion_matrix_is_exact"),
    ("NOT_READY provider conclusion accepts success",
     "admissible/attestation.py",
     "    if readiness == READINESS_NOT_READY:\n        return frozenset()",
     '    if readiness == READINESS_NOT_READY:\n        return frozenset({"success"})',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_provider_conclusion_matrix_is_exact"),
    ("observer signature subsumes independent review authorities",
     "admissible/attestation.py",
     '    "isolation", "dependencies", "command_digests", "review_digests",\n',
     '    "isolation", "dependencies", "command_digests", "review_digests",\n    "attestation_digests", "author_attestation_digests",\n',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_review_signatures_are_not_re_signed_by_the_observer"),
    ("out of band signed reviews are discarded",
     "admissible/github.py",
     "        verified = verified + extra_reviews",
     "        verified = verified",
     "tests.test_admissible_final_closure.AttestationClosureTest.test_out_of_band_authorities_added_after_observation_are_bound"),
    ("out of band signed authorship is discarded",
     "admissible/github.py",
     "        authorships = authorships + extra_authorships",
     "        authorships = authorships",
     "tests.test_admissible_final_closure.AttestationClosureTest.test_out_of_band_authorities_added_after_observation_are_bound"),
    ("public finalize dependency injection restored",
     "admissible/github.py",
     "def finalize(store, preview_path: Path | str, *, signer, expected_sha: str,\n             now: int, policy_root: Path | str | None = None,",
     "def finalize(store, preview_path: Path | str, *, signer, expected_sha: str,\n             dependencies: tuple = (), now: int,\n             policy_root: Path | str | None = None,",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_public_finalize_has_no_dependency_injection_parameter"),
    ("cached receipt authentication removed",
     "admissible/receipt.py",
     "            verify_receipt(stored, signer)",
     "            pass",
     "tests.test_admissible_evaluation_core.CachedReceiptAuthenticationTest.test_forged_cached_receipt_is_refused"),
    ("cached receipt complete body comparison removed",
     "admissible/receipt.py",
     "        if stored.body_digest != body_digest or actual != body:",
     "        if False:",
     "tests.test_admissible_evaluation_core.CachedReceiptAuthenticationTest.test_authentic_but_conflicting_cached_receipt_is_refused"),
    ("cached receipt hint returned before transaction",
     "admissible/receipt.py",
     "    if hinted is not None:\n        authenticated_expected(hinted, where=\"cached\")",
     "    if hinted is not None:\n        return authenticated_expected(hinted, where=\"cached\")",
     "tests.test_admissible_evaluation_core.CachedReceiptAuthenticationTest.test_authenticated_hint_is_never_returned_before_transactional_reread"),
    ("cached receipt transactional reread removed",
     "admissible/receipt.py",
     "               preflight=receipt_transaction_preflight)",
     "               preflight=None)",
     "tests.test_admissible_evaluation_core.CachedReceiptAuthenticationTest.test_racing_forged_cached_receipt_is_refused_inside_transaction"),
    ("transaction cached receipt return skips reauthentication",
     "admissible/receipt.py",
     "        return authenticated_expected(duplicate.receipt,\n                                      where=\"transaction-cached\")",
     "        return duplicate.receipt",
     "tests.test_admissible_evaluation_core.CachedReceiptAuthenticationTest.test_every_cached_or_new_receipt_return_is_reauthenticated"),
    ("new receipt return skips reauthentication",
     "admissible/receipt.py",
     '    return authenticated_expected(stored, where="newly stored")',
     "    return stored",
     "tests.test_admissible_evaluation_core.CachedReceiptAuthenticationTest.test_every_cached_or_new_receipt_return_is_reauthenticated"),
    ("interrupt recovery expected receipt digest changes issued_at",
     "admissible/github.py",
     '        "issued_at": parts.issued_at,',
     '        "issued_at": parts.issued_at + 1,',
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_expected_finalization_digest_matches_the_issued_body"),
    ("receipt issuer accepts duplicate evidence digests",
     "admissible/receipt.py",
     "    if len(claimed_items) != len(set(claimed_items)):",
     "    if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_duplicate_evidence_digests_are_refused"),
    ("receipt issuer accepts evidence for another artifact",
     "admissible/receipt.py",
     '        if (document.get("repository") != repository\n                or document.get("commit_sha") != commit_sha\n                or document.get("tree_sha") != tree_sha\n                or document.get("policy_digest") != policy_digest):',
     "        if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_every_supplied_evidence_record_is_receipt_bound"),
    ("authenticated review attribution may name unsupplied evidence",
     "admissible/receipt.py",
     "        row = evidence_rows.get(digest)",
     "        row = evidence_rows.get(digest) or next(iter(evidence_rows.values()), None)",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_authenticated_review_digest_must_be_receipt_bound_and_supplied"),
    ("authenticated review attribution may resolve to command evidence",
     "admissible/receipt.py",
     '        if (type(record) is not evidence_module.ReviewEvidence\n                or record.verdict != "approve"):',
     "        if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_authenticated_review_must_resolve_to_a_review_record"),
    ("authenticated review attribution may resolve to rejection",
     "admissible/receipt.py",
     '        if (type(record) is not evidence_module.ReviewEvidence\n                or record.verdict != "approve"):',
     "        if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_authenticated_review_must_be_an_approval"),
    ("authenticated review digest type guard removed",
     "admissible/receipt.py",
     '        if (type(digest) is not str or len(digest) != 64\n                or any(character not in "0123456789abcdef"\n                       for character in digest)):',
     "        if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_authenticated_review_digest_type_is_closed"),
    ("authenticated reviewer key type guard removed",
     "admissible/receipt.py",
     "        if type(key_id) is not str or not key_id.strip():",
     "        if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_authenticated_review_key_id_is_nonempty_text"),
    ("receipt issuer accepts duplicate authenticated review attributions",
     "admissible/receipt.py",
     "    if len(normalized) != len(set(normalized)):\n        raise ReceiptError(\n            \"a workflow receipt cannot repeat one authenticated review \"",
     "    if False:\n        raise ReceiptError(\n            \"a workflow receipt cannot repeat one authenticated review \"",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_duplicate_authenticated_review_attributions_are_refused"),
    ("receipt issuer accepts duplicate dependency edges",
     "admissible/receipt.py",
     "    if len(normalized) != len(set(normalized)):\n"
     "        raise ReceiptError(\n"
     "            \"a workflow receipt cannot bind the same dependency edge more \"\n"
     "            \"than once; nothing was anchored\")\n"
     "    return tuple(normalized)",
     "    return tuple(dict.fromkeys(normalized))",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_duplicate_dependency_edges_are_refused"),
    ("receipt issuer ignores conflicting evidence attachment",
     "admissible/receipt.py",
     "            if actual != wanted:",
     "            if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_conflicting_preexisting_evidence_attachment_is_refused"),
    ("receipt issuer ignores conflicting dependency attachment",
     "admissible/receipt.py",
     '                    if expected.get(edge) != row["recorded_at"]:',
     "                    if False:",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_first_receipt_refuses_unsigned_dependency_on_another_commit"),
    ("cached receipt return skips attachment correspondence",
     "admissible/receipt.py",
     "            ensure_attachment_correspondence(require_present=True)",
     "            pass",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_cached_retry_rechecks_its_evidence_metadata"),
    ("receipt evidence attachment escapes the head transaction",
     "admissible/receipt.py",
     "    event = _event_for(body, body_digest)",
     "    for _attachment in evidence_rows.values():\n"
     "        _record = _attachment[\"record\"]\n"
     "        _document = evidence_module.evidence_to_dict(_record)\n"
     "        store.put_evidence(\n"
     "            digest=_attachment[\"digest\"], kind=_attachment[\"kind\"],\n"
     "            repository=_attachment[\"repository\"],\n"
     "            commit_sha=_attachment[\"commit_sha\"],\n"
     "            tree_sha=_attachment[\"tree_sha\"],\n"
     "            policy_digest=_attachment[\"policy_digest\"],\n"
     "            record=_document)\n"
     "    event = _event_for(body, body_digest)",
     "tests.test_admissible_evaluation_core.ReceiptIssuanceCorrespondenceTest.test_evidence_attachment_and_receipt_commit_atomically"),
    ("finalize ignores changed expected receipt body",
     "admissible/github.py",
     "        if actual_body_digest != expected_body_digest:",
     "        if False:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_finalize_refuses_if_revalidation_changes_the_expected_body"),
    ("github.py a reviewer and observer share one physical secret",
     "admissible/github.py",
     "    if overlaps:",
     "    if False:",
     "tests.test_admissible_final_closure"),
    ("github.py supplied admission signer skips trust-domain comparison",
     "admissible/github.py",
     "        admission_signer=signer)\n"
     "    body_arguments = _receipt_body_arguments(parts)",
     "        admission_signer=None)\n"
     "    body_arguments = _receipt_body_arguments(parts)",
     "tests.test_admissible_final_closure.DistinctCredentialTest.test_supplied_signer_is_compared_without_an_environment_copy"),
    ("cli.py policy parent options silently override authority target",
     "admissible/cli.py",
     "    with_repo(listing)\n\n"
     "    finalize = commands.add_parser(\"finalize\", add_help=False)",
     "    with_repo(listing)\n"
     "    with_repo(policy)\n\n"
     "    finalize = commands.add_parser(\"finalize\", add_help=False)",
     "tests.test_admissible_final_closure.PolicyGenerationTest.test_policy_options_before_the_action_are_refused"),
    ("hosted workflow accepts candidate isolation",
     ".github/workflows/admissible-gate.yml",
     "          ADMISSIBLE_ISOLATION: none",
     "          ADMISSIBLE_ISOLATION: ${{ inputs.isolation }}",
     "tests.test_admissible_hosted_contract"),
    ("hosted workflow upload pin removed",
     ".github/workflows/admissible-gate.yml",
     "        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
     "        uses: actions/upload-artifact@main",
     "tests.test_admissible_hosted_contract"),
    ("hosted workflow red preview is not uploaded",
     ".github/workflows/admissible-gate.yml",
     "      - name: persist the preview handoff\n        if: ${{ always() && steps.gate.outputs.preview != '' }}",
     "      - name: persist the preview handoff\n        if: ${{ success() && steps.gate.outputs.preview != '' }}",
     "tests.test_admissible_hosted_contract"),
    ("hosted artifact name drops run attempt",
     ".github/workflows/admissible-gate.yml",
     "        with:\n          name: admissible-preview-${{ steps.head.outputs.sha }}-attempt-${{ github.run_attempt }}",
     "        with:\n          name: admissible-preview-${{ steps.head.outputs.sha }}",
     "tests.test_admissible_hosted_contract"),
    ("hosted artifact drops preview sha256 receipt",
     ".github/workflows/admissible-gate.yml",
     "            ${{ steps.preview_receipt.outputs.path }}",
     "            # preview receipt omitted",
     "tests.test_admissible_hosted_contract"),
    ("hosted preview sha256 is fabricated",
     ".github/workflows/admissible-gate.yml",
     "          digest = hashlib.sha256(body).hexdigest()",
     "          digest = \"0\" * 64",
     "tests.test_admissible_hosted_contract"),
    ("hosted workflow receives an evaluation secret",
     ".github/workflows/admissible-gate.yml",
     "          ADMISSIBLE_EVALUATION_KEYRING: \"\"",
     "          ADMISSIBLE_EVALUATION_KEYRING: ${{ secrets.OBSERVER_KEYS }}",
     "tests.test_admissible_hosted_contract"),
    ("generated caller recommends in-tree reviews",
     "admissible/templates/consumer-workflow.yml",
     "          --reviews /trusted/out-of-band/reviews.json",
     "          --reviews .admissible/reviews.json",
     "tests.test_admissible_hosted_contract"),
    ("composite provider matrix drops NOT_READY",
     ".github/actions/admissible/action.yml",
     "      NOT_READY -> no provider conclusion is admissible",
     "      NOT_READY -> success",
     "tests.test_admissible_hosted_contract"),
    ("composite trusts its reported readiness",
     ".github/actions/admissible/action.yml",
     "readiness it independently recomputes from evidence and",
     "readiness this action reports, without recomputation, from",
     "tests.test_admissible_hosted_contract"),
    ("provider matrix trusts observer readiness",
     "README.md",
     "readiness the finalizer recomputes",
     "readiness the observer signs",
     "tests.test_admissible_hosted_contract"),
    ("observer re-signs review and authorship roles",
     "README.md",
     "**separate authenticated roles**",
     "**one observer-authenticated role**",
     "tests.test_admissible_hosted_contract"),
    ("observer isolation assertion removed from docs",
     "README.md",
     "**observer independently asserts isolation**",
     "**preview asserts isolation**",
     "tests.test_admissible_hosted_contract"),
    ("README trusts policy before selecting durable home",
     "README.md",
     "export ADMISSIBLE_HOME=/var/lib/admissible",
     "export ADMISSIBLE_HOME_AFTER_POLICY_TRUST=/var/lib/admissible",
     "tests.test_admissible_hosted_contract"),
    ("moving-state export loses its signed prefix bound",
     "docs/DEVELOPER_WORKFLOW.md",
     "admissible-trust export --through-head HEAD_HASH "
     "--out journal-prefix.json",
     "admissible-trust export --out journal-prefix.json",
     "tests.test_admissible_hosted_contract"),
    ("workflow evidence accepts empty missed check ids",
     "protocol/workflow-evidence.schema.json",
     "        \"missed_check_ids\": {\n          \"type\": \"array\",\n          \"items\": {\n            \"type\": \"string\",\n            \"minLength\": 1",
     "        \"missed_check_ids\": {\n          \"type\": \"array\",\n          \"items\": {\n            \"type\": \"string\",\n            \"minLength\": 0",
     "tests.test_admissible_hosted_contract"),
    ("evaluation schema drops preview schema binding",
     "protocol/evaluation-attestation.schema.json",
     "        \"preview_schema\",\n",
     "",
     "tests.test_admissible_hosted_contract"),
    ("demo hides its temporary store",
     "examples/developer-workflow/demo.sh",
     "temporary demonstration store",
     "durable production store",
     "tests.test_admissible_hosted_contract"),
    ("demo lowers the documented payment floor",
     "examples/developer-workflow/show.py",
     "the 18-unit cost",
     "the 17-unit cost",
     "tests.test_admissible_hosted_contract"),
    ("installed wheel loses its console entry point",
     "pyproject.toml",
     'admissible = "admissible.cli:main"',
     'admissible-disabled = "admissible.cli:main"',
     "tests.test_admissible_external_consumer.InstalledExternalConsumerTest"),
    ("installed wheel omits the evaluation schema",
     "pyproject.toml",
     'include = ["admissible*", "fcd*", "rga*", "atlas*", "server*", "protocol*"]',
     'include = ["admissible*", "fcd*", "rga*", "atlas*", "server*"]',
     "tests.test_admissible_quality.WheelContractTest.test_the_wheel_evaluation_schema_has_the_closed_observer_contract"),
    ("cli interrupt recovery looks up a different receipt body",
     "admissible/cli.py",
     "            candidate = reopened.workflow_receipt_by_body(expected_body_digest)",
     '            candidate = reopened.workflow_receipt_by_body("0" * 64)',
     "tests.test_admissible_release_closure.InterruptedReceiptIdentityContractTest.test_recovery_queries_only_the_exact_expected_receipt_body"),
    ("cli finalize drops the precomputed receipt body guard",
     "admissible/cli.py",
     "            expected_body_digest=expected_body_digest)",
     "            expected_body_digest=None)",
     "tests.test_admissible_release_closure.InterruptedReceiptIdentityContractTest.test_finalize_precomputes_identity_with_the_same_issued_time"),
    ("cli import reads an unbounded journal after stat",
     "admissible/cli.py",
     "            raw = handle.read(store_module.MAX_JOURNAL_BYTES + 1)",
     "            raw = handle.read()",
     "tests.test_admissible_release_closure.BoundedImportContractTest.test_import_uses_a_bounded_read_even_after_the_stat_check"),
    ("cli output-copy failure reports attestation readiness",
     "admissible/cli.py",
     '                    document["readiness"] = READINESS_NOT_READY',
     '                    document["readiness"] = READINESS_READY_FOR_ATTESTATION',
     "tests.test_admissible_release_closure.AnchoredPartialOutputContractTest.test_output_copy_failure_does_not_relabel_admission_as_ready"),
    ("cli help conflates run success with admission",
     "admissible/cli.py",
     "  run:      0 = CHECKS_PASSED only; never admission",
     "  run:      0 = checks passed or admission",
     "tests.test_admissible_release_closure.PublicExitContractTest.test_global_help_says_run_zero_is_only_checks_passed"),
    ("cli corrupt stored JSON escapes as a traceback",
     "admissible/cli.py",
     "            identity_module.IdentityError, ConfigError,\n"
     "            json.JSONDecodeError) as error:",
     "            identity_module.IdentityError, ConfigError) as error:",
     "tests.test_admissible_release_closure.PublicExitContractTest.test_explain_turns_corrupt_stored_json_into_a_machine_failure"),
    ("cli blocked JSON omits NOT_READY",
     "admissible/cli.py",
     '            "state": BLOCKED,\n'
     '            # An operational failure establishes nothing, so it carries the\n'
     '            # same readiness key a decision does. A consumer reading `readiness`\n'
     '            # must never have to special-case the shape it gets back.\n'
     '            "readiness": READINESS_NOT_READY,',
     '            "state": BLOCKED,\n'
     '            # An operational failure establishes nothing, so it carries the\n'
     '            # same readiness key a decision does. A consumer reading `readiness`\n'
     '            # must never have to special-case the shape it gets back.\n'
     '            "readiness": READINESS_READY_FOR_ATTESTATION,',
     "tests.test_admissible_release_closure.PublicExitContractTest.test_explain_turns_corrupt_stored_json_into_a_machine_failure"),
    ("cli verify JSON omits actionable remediation",
     "admissible/cli.py",
     '            document["remediation"] = list(remediation)',
     '            document["remediation"] = []',
     "tests.test_admissible_release_closure.PublicExitContractTest.test_unknown_verify_json_has_the_stable_nonzero_envelope"),
    ("cli explain JSON calls UNKNOWN ready for attestation",
     "admissible/cli.py",
     '            reported = (report.state if not signature_problems\n'
     '                        else "UNVERIFIED")\n'
     '            document["state"] = reported\n'
     '            document["readiness"] = (\n'
     '                READINESS_READY_FOR_ATTESTATION\n'
     '                if reported == standing_module.CURRENT else READINESS_NOT_READY)',
     '            reported = (report.state if not signature_problems\n'
     '                        else "UNVERIFIED")\n'
     '            document["state"] = reported\n'
     '            document["readiness"] = READINESS_READY_FOR_ATTESTATION',
     "tests.test_admissible_release_closure.PublicExitContractTest.test_unknown_explain_json_has_the_stable_nonzero_envelope"),
    ("cli status JSON omits actionable remediation",
     "admissible/cli.py",
     '        document["remediation"] = list(_status_next_steps(\n'
     '            reported, found.commit_sha, key_problem))',
     '        document["remediation"] = []',
     "tests.test_admissible_release_closure.PublicExitContractTest.test_unknown_status_json_has_the_stable_nonzero_envelope"),
    ("cli observer isolation is optional",
     "admissible/cli.py",
     '        "--isolation", required=True, choices=runner_module.ISOLATION_MODES,',
     '        "--isolation", required=False, choices=runner_module.ISOLATION_MODES,',
     "tests.test_admissible_release_closure.ObserverCliContractTest.test_observer_isolation_is_an_explicit_required_input"),
    ("cli deterministic prefix option is hidden",
     "admissible/cli.py",
     '        "--through-head", dest="through_head", default=None, metavar="HASH",',
     '        "--bounded-prefix", dest="through_head", default=None, metavar="HASH",',
     "tests.test_admissible_release_closure.BoundedExportContractTest.test_public_cli_exposes_the_deterministic_signed_prefix"),
    ("late out-of-band authorities are evaluated at observer time",
     "admissible/github.py",
     "        authorships=authorships, now=authority_time, attempt_id=attempt_id)",
     "        authorships=authorships, now=observed_at, attempt_id=attempt_id)",
     "tests.test_admissible_final_closure.AttestationClosureTest.test_later_out_of_band_authorities_do_not_need_observer_resigning"),
    ("late out-of-band authority time is omitted from the receipt",
     "admissible/github.py",
     "        dependencies=declared, issued_at=authority_time)",
     "        dependencies=declared, issued_at=observed_at)",
     "tests.test_admissible_final_closure.AttestationClosureTest.test_later_out_of_band_authorities_do_not_need_observer_resigning"),
    ("future out-of-band authority is accepted",
     "admissible/github.py",
     "    if authority_time > now + MAX_CLOCK_SKEW_SECONDS:",
     "    if False and authority_time > now + MAX_CLOCK_SKEW_SECONDS:",
     "tests.test_admissible_final_closure.AttestationClosureTest.test_out_of_band_authority_ahead_of_finalizer_clock_refuses"),
    ("finalize does not request a transactional policy recheck",
     "admissible/github.py",
     "        _require_current_policy=True,",
     "        _require_current_policy=False,",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_policy_revocation_before_receipt_commit_refuses"),
    ("receipt issuance skips its current policy precondition",
     "admissible/receipt.py",
     "        if _require_current_policy:\n            try:",
     "        if False and _require_current_policy:\n            try:",
     "tests.test_admissible_evaluation_core.EvaluationStatementContractTest.test_policy_revocation_before_receipt_commit_refuses"),
    ("receipt issuance ignores unsigned extra dependency edges",
     "admissible/receipt.py",
     "        if actual_dependency_rows != expected_dependency_rows:",
     "        if False:",
     "tests.test_admissible_durable_core_security.AuthenticatedStandingSecurityTest.test_unsigned_extra_edge_blocks_receipt_issuance"),
    ("atomic helper leaves commit failure outside rollback",
     "admissible/store.py",
     '            self._connection.execute("COMMIT")\n        except BaseException:',
     "            pass\n        except BaseException:",
     "tests.test_admissible_durable_core_security.PolicyTransactionSecurityTest.test_failed_commit_rolls_back_before_later_authority_reads"),
    ("local standing inherits the export construction ceiling",
     "admissible/store.py",
     "            journal_id, _enforce_transfer_limit=False)",
     "            journal_id, _enforce_transfer_limit=True)",
     "tests.test_admissible_durable_core_security.ImportMultiplicitySecurityTest.test_transfer_ceiling_does_not_limit_local_authenticated_standing"),
    ("local standing inherits the import parse ceiling",
     "admissible/store.py",
     "            bundle, _enforce_transfer_limit=False)",
     "            bundle, _enforce_transfer_limit=True)",
     "tests.test_admissible_durable_core_security.ImportMultiplicitySecurityTest.test_transfer_ceiling_does_not_limit_local_authenticated_standing"),
    ("bounded export help disguises a historical cut as incremental",
     "admissible/cli.py",
     '        help="export an explicit historical journal cut ending at this "',
     '        help="export a deterministic journal prefix ending at this "',
     "tests.test_admissible_release_closure.BoundedExportContractTest.test_prefix_help_calls_the_selection_historical_not_incremental"),
    ("oversized export hides that the selected cut is historical",
     "admissible/store.py",
     '                "with through_head only for an explicit historical cut. "',
     '                "with through_head as an incremental part. "',
     "tests.test_admissible_durable_core_security.ImportMultiplicitySecurityTest.test_historical_prefixes_are_cumulative_not_size_chunks"),
    ("moving-state guide claims historical cuts bypass the ceiling",
     "docs/DEVELOPER_WORKFLOW.md",
     "A selected prefix is a historical cut, not a path around the ceiling.",
     "A selected prefix is a historical cut and a path around the ceiling.",
     "tests.test_admissible_hosted_contract.PublicHandoffContractTest.test_moving_state_uses_a_bounded_signed_prefix"),
    ("receipt issuance skips prior bound evidence validation",
     "admissible/receipt.py",
     "        validate_prior_evidence(prior_evidence)",
     "        validate_prior_evidence({})",
     "tests.test_admissible_durable_core_security.AuthenticatedStandingSecurityTest.test_new_issuance_refuses_when_prior_evidence_metadata_conflicts"),
    ("receipt dependency time remains arrival ordered",
     "admissible/receipt.py",
     "                  and expected_time < prior_time):",
     "                  and False):",
     "tests.test_admissible_durable_core_security.AuthenticatedStandingSecurityTest.test_repeated_signed_edge_is_order_independent_when_older_authority_arrives_later"),
    ("schema blocks canonical lowering for an older signed dependency",
     "admissible/store.py",
     "CREATE TRIGGER IF NOT EXISTS dependencies_no_update\n"
     "    BEFORE UPDATE ON dependencies\n"
     "    WHEN NEW.consumer_repository <> OLD.consumer_repository",
     "CREATE TRIGGER IF NOT EXISTS dependencies_no_update\n"
     "    BEFORE UPDATE ON dependencies\n"
     "    WHEN 1",
     "tests.test_admissible_durable_core_security.AuthenticatedStandingSecurityTest.test_repeated_signed_edge_is_order_independent_when_older_authority_arrives_later"),
    ("schema v5 migration keeps the strict dependency trigger",
     "admissible/store.py",
     '            "DROP TRIGGER IF EXISTS dependencies_no_update")',
     '            "DROP TRIGGER IF EXISTS dependencies_no_update_DISABLED")',
     "tests.test_admissible_durable_core_security.PolicyTransactionSecurityTest.test_schema_v5_migrates_dependency_time_to_canonical_minimum"),
    ("import dependency time follows receipt array order",
     "admissible/store.py",
     '                    and stored["recorded_at"] in\n'
     "                    supported_dependency_times[edge]):",
     "                    and False):",
     "tests.test_admissible_durable_core_security.ImportMultiplicitySecurityTest.test_import_dependency_time_is_independent_of_receipt_array_order"),
    ("receipt issuance omits repository-wide authenticated preflight",
     "admissible/receipt.py",
     "        authenticated_repository_preflight()",
     "        pass",
     "tests.test_admissible_durable_core_security.AuthenticatedStandingSecurityTest.test_cached_and_new_issuance_refuse_other_commit_corruption"),
    ("store skips the before-extend transaction preflight",
     "admissible/store.py",
     "            if before_extend is not None:\n"
     "                before_extend()",
     "            if False and before_extend is not None:\n"
     "                before_extend()",
     "tests.test_admissible_durable_core_security.AuthenticatedStandingSecurityTest.test_new_issuance_refuses_unsigned_edge_on_other_commit"),
    ("store exact-head return precedes receipt transaction preflight",
     "admissible/store.py",
     "            if before_extend is not None:\n"
     "                before_extend()\n"
     "            if current is not None and current.receipt_hash == head_receipt.receipt_hash:\n"
     "                self._rollback()\n"
     "                self._reset_busy_timeout(busy_timeout_ms)\n"
     "                return current",
     "            if current is not None and current.receipt_hash == head_receipt.receipt_hash:\n"
     "                self._rollback()\n"
     "                self._reset_busy_timeout(busy_timeout_ms)\n"
     "                return current\n"
     "            if before_extend is not None:\n"
     "                before_extend()",
     "tests.test_admissible_durability.AtomicIssuanceTest.test_exact_head_race_still_runs_cached_repository_preflight"),
]

USAGE = ("usage: sabotage_admissible.py "
         "[--match LABEL_TEXT | --legacy-only | --separation-only]")

# Both phases run by default, because "the harness passed" has to mean both.
RUN_LEGACY = True
RUN_SEPARATION = True

if len(sys.argv) > 1:
    if sys.argv[1:] == ["--legacy-only"]:
        RUN_SEPARATION = False
    elif sys.argv[1:] == ["--separation-only"]:
        RUN_LEGACY = False
    elif len(sys.argv) != 3 or sys.argv[1] != "--match":
        raise SystemExit(USAGE)
    else:
        selected = [case for case in CASES if sys.argv[2] in case[0]]
        if len(selected) != 1:
            labels = "\n  ".join(case[0] for case in selected) or "none"
            raise SystemExit(
                f"--match must select exactly one case; matched:\n  {labels}")
        CASES = selected
        # A focused legacy run is a debugging aid for one product guard, so it
        # answers about that guard alone rather than rebuilding four wheels.
        RUN_SEPARATION = False

if not RUN_LEGACY:
    CASES = []

# ---------------------------------------------------------------------------
# Every byte of every target, captured before anything is edited. This is the
# only thing restoration is ever allowed to restore from: reading a file back
# after an edit would restore the sabotage.
ORIGINALS = {}
for _, _relative, _, _, _ in CASES:
    if _relative not in ORIGINALS:
        ORIGINALS[_relative] = (ROOT / _relative).read_bytes()

TARGETS = tuple(sorted(ORIGINALS))
DIGESTS = {name: hashlib.sha256(body).hexdigest()
           for name, body in ORIGINALS.items()}


def restore_all():
    """Put every target back. Safe to call any number of times."""

    for name, body in ORIGINALS.items():
        path = ROOT / name
        try:
            if path.read_bytes() != body:
                path.write_bytes(body)
        except OSError:
            # Losing the file entirely is still recoverable: we hold the bytes.
            try:
                path.write_bytes(body)
            except OSError as error:  # pragma: no cover - disk-level failure
                print(f"CANNOT RESTORE {name}: {error}", file=sys.stderr)


def _restore_and_die(number, _frame):  # pragma: no cover - signal path
    restore_all()
    # Re-raise through the default handler so the exit status stays honest
    # about why this process stopped.
    signal.signal(number, signal.SIG_DFL)
    os.kill(os.getpid(), number)


atexit.register(restore_all)
for _signal in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    try:
        signal.signal(_signal, _restore_and_die)
    except (ValueError, OSError):  # pragma: no cover - not the main thread
        pass


def integrity_report():
    """Every target that is not byte-identical to how this run found it."""

    damaged = []
    for name in TARGETS:
        path = ROOT / name
        try:
            body = path.read_bytes()
        except OSError as error:
            damaged.append(f"{name}: unreadable ({error})")
            continue
        if hashlib.sha256(body).hexdigest() != DIGESTS[name]:
            damaged.append(f"{name}: content differs from the pre-run capture")
    return damaged


# The two sabotage shapes this harness writes that could never be real code.
# `if True` and `pass` replacements are indistinguishable from legitimate source
# and are covered by the byte-identity check instead.
RESIDUE_MARKERS = ("if False:", "if false; then")


def residue_report():
    """Any live sabotage marker in the shipped package or the workflows.

    This is deliberately independent of the byte-identity check above. That one
    proves *this* run left nothing behind; this one proves the tree did not
    already carry residue from an earlier run that was killed before it could
    restore -- residue that could otherwise be committed and then pass forever.
    """

    found = []
    for base in (ROOT / "admissible", ROOT / ".github"):
        for path in sorted(base.rglob("*")):
            if (not path.is_file() or "__pycache__" in path.parts
                    or path.suffix not in (".py", ".yml", ".yaml")):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for marker in RESIDUE_MARKERS:
                if marker in text:
                    found.append(
                        f"{path.relative_to(ROOT)} still contains {marker!r}")
    return found


failures = []
for case_index, (label, relative, needle, replacement, suite) in enumerate(CASES):
    path = ROOT / relative
    original = ORIGINALS[relative]
    text = original.decode("utf-8")
    occurrences = text.count(needle)
    if occurrences != 1:
        print(f"SKIP  {label}: anchor occurs {occurrences} times, expected 1")
        failures.append(label)
        continue
    path.write_text(text.replace(needle, replacement, 1), encoding="utf-8")
    detail = ""
    try:
        # A same-length mutation written and restored inside one filesystem
        # timestamp tick can otherwise match a stale timestamp-based .pyc.
        # Give every mutation a cache namespace that did not exist before this
        # process and forbid writes there: the named suite must execute the
        # mutated source, and restoration must not leave executable sabotage
        # behind after the source bytes are restored.
        cache_prefix = (Path(tempfile.gettempdir()) /
                        f"admissible-sabotage-pyc-{os.getpid()}-{case_index}")
        result = subprocess.run(
            [PYTHON, "-B", "-X", f"pycache_prefix={cache_prefix}",
             "-m", "unittest", suite, "-q"], cwd=str(ROOT),
            capture_output=True, timeout=SUITE_TIMEOUT_SECONDS)
        returncode = result.returncode
        detail = " ".join(result.stderr.decode().strip().splitlines()[-1:])
    except subprocess.TimeoutExpired:
        # A hung suite proves nothing either way, so it is reported as an
        # undetected sabotage rather than quietly counted as red.
        returncode = 0
        detail = f"suite did not finish inside {SUITE_TIMEOUT_SECONDS}s"
    except OSError as error:
        returncode = 0
        detail = f"the suite could not be started: {error}"
    finally:
        path.write_bytes(original)
    status = "RED (good)" if returncode != 0 else "GREEN (BAD: undetected)"
    print(f"{status:22} {label} -> {suite}: {detail}")
    if returncode == 0:
        failures.append(label)

restore_all()
damaged = integrity_report()
residue = residue_report()

print()
print(f"sabotage cases: {len(CASES)} over {len(TARGETS)} source file(s)")
print("undetected sabotage:", failures or "none")
print("source integrity:", damaged or "every target byte-identical to pre-run")
print("live sabotage residue:", residue
      or f"none; scanned admissible/ and .github/ for {RESIDUE_MARKERS}")


# ---------------------------------------------------------------------------
# Phase two: the package separation guards, each in a disposable clone.
#
# Reported separately and counted separately. A kill here is not the same claim
# as a kill above: the cases above prove that one product guard is watched by
# one suite, and these prove that an architectural property -- two
# distributions, one owner per namespace, a router that reads only argv --
# survives being attacked at the place it actually lives.

def run_separation_phase():
    """Every registered SEP mutant, judged in its own throwaway checkout."""

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from tests.architecture import separation_guards as guards
    except ImportError as error:
        # Never silently skipped: a separation phase that did not run reads
        # exactly like a separation that holds.
        print(f"SEPARATION HARNESS UNAVAILABLE: {error}", file=sys.stderr)
        return None

    print()
    print("-" * 78)
    print("package separation guards: SEP1-SEP12, each mutant in a "
          "disposable clone")
    print("-" * 78)

    # Printed before anything is judged, because every verdict below depends on
    # it: a mutant that could reach the network or this developer's home was
    # not run in the conditions this phase claims to run it in.
    isolation = guards.network_denial_problem()
    print("isolation:", (
        f"BROKEN -- {isolation}" if isolation else
        f"{guards.network_boundary()} refuses every socket, at both the depth "
        "this harness starts and the depth the tests run at; the environment is "
        f"{len(guards.FORCED_ENVIRONMENT_NAMES)} harness-owned variables and a "
        "private home inside each disposable workspace"))

    # And who wrote the evidence each verdict below rests on. The tested
    # process is the one thing in this phase that cannot be trusted to describe
    # itself, so what it is *not* given is part of the receipt.
    print("evidence channel: a sealed observer outside each clone signs one "
          f"{guards.FRAME_VERSION} frame per run with a per-run key on an "
          "anonymous pipe; the tested process has no descriptor on it, no key, "
          "no nonce and no path -- its argv is the test ids and nothing else")

    # Every source file and its bytes, before a single clone is made. This
    # phase claims not to touch the working tree at all, which is a wider claim
    # than the byte-identity above -- that one covers the legacy targets, this
    # one covers everything -- and a claim is worth checking.
    tree_before = guards.worktree_digest(ROOT)

    control = guards.control_receipt(ROOT)
    control_ok = control.verdict == guards.PASSED
    print(f"{'CONTROL ' + control.verdict:22} unmutated candidate: "
          f"{control.detail}")

    receipts = []
    for mutant in guards.MUTANTS:
        receipt = guards.evaluate(mutant, root=ROOT)
        receipts.append(receipt)
        status = {
            guards.KILLED: "RED (good)",
            guards.SURVIVED: "GREEN (BAD: undetected)",
        }.get(receipt.verdict, "ERROR (BAD: no claim)")
        print(f"{status:22} {receipt.mutant_id} -> {receipt.kills}: "
              f"{receipt.detail}")

    killed = [item for item in receipts if item.verdict == guards.KILLED]
    survived = [item for item in receipts if item.verdict == guards.SURVIVED]
    errored = [item for item in receipts
               if item.verdict not in (guards.KILLED, guards.SURVIVED)]

    print()
    print(f"separation mutants: discovered {len(receipts)}, "
          f"killed {len(killed)}, survived {len(survived)}, "
          f"errors {len(errored)}")
    print("negative control:",
          "the unmutated candidate passes every named test"
          if control_ok else f"BROKEN -- {control.detail}")
    print("per-invariant receipt:")
    for sep in guards.SEP_IDS:
        rows = [item for item in receipts if item.sep == sep]
        outcome = ("all killed" if rows and all(item.ok for item in rows)
                   else "NOT PROVED")
        names = ", ".join(item.mutant_id for item in rows) or "no mutant"
        print(f"  {sep:6} {outcome:11} {len(rows)} mutant(s): {names}")
        print(f"         {guards.INVARIANTS[sep]}")
    signatures = guards.signature_problems()
    print("expected-failure signatures:", signatures
          or f"all {len(guards.MUTANTS)} specific, unique and applicable; a "
             "kill is the registered assertion, not merely a red run")
    orphans = guards.orphaned_workspaces()
    moved = guards.worktree_digest(ROOT) != tree_before
    print("clone residue:", orphans
          or "none; every disposable checkout was removed")
    print("working tree:", "CHANGED BY THIS PHASE" if moved else
          "byte-identical to the capture taken before the first clone")
    return bool(survived or errored or orphans or moved or not control_ok
                or isolation or signatures)


separation_problem = run_separation_phase() if RUN_SEPARATION else False
if RUN_SEPARATION and separation_problem is None:
    separation_problem = True

sys.exit(1 if (failures or damaged or residue or separation_problem) else 0)
