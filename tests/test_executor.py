import contextlib
import fnmatch
import io
import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

import executor


def fenced(body: str) -> str:
    return f"{executor.BEGIN_MARKER}\n{body}{executor.END_MARKER}"


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.worktree = Path("D:/worktree")
        self.config = {
            "allowlisted_files": ["src/**", "tests/**"],
            "allowlisted_commands": ["python -m unittest discover -s tests -v"],
            "risk_levels": ["low", "medium", "high"],
            "task_limits": {
                "local_attempts": 3, "paid_reviews": 2,
                "changed_files": 5, "command_timeout_seconds": 300,
            },
        }
        self.task = {
            "type": "implementation_task", "task_id": "test-task",
            "objective": "Test executor.", "allowed_files": ["src/app.py"],
            "allowed_commands": ["python -m unittest discover -s tests -v"],
            "acceptance_criteria": ["Tests pass."], "risk": "low",
            "requires_human_approval": False,
            "limits": {
                "local_attempts": 1, "paid_reviews": 1,
                "changed_files": 1, "command_timeout_seconds": 30,
            },
        }

    def test_contract_rejection(self):
        invalid = dict(self.task)
        invalid.pop("limits")
        errors = executor.validate_executor_task(invalid, self.worktree, self.config)
        self.assertTrue(any("Missing task keys: limits" in item for item in errors))

    def test_context_prompt_includes_read_only_files(self):
        prompt = executor.implementation_prompt(
            self.task, "src/app.py", "old\n", {"src/version.h": "#define VERSION 1\n"}
        )
        self.assertIn("Read-only context (do not output these files)", prompt)
        self.assertIn("src/version.h", prompt)
        self.assertIn("#define VERSION 1", prompt)

    def test_fence_inside_markers_is_stripped(self):
        errors, body = executor.extract_fenced_body(
            "<<<FILE>>>\n```c\nint main(void) {}\n```\n<<<END>>>"
        )
        self.assertEqual(errors, [])
        self.assertEqual(body, "int main(void) {}")

    def test_repair_loop_succeeds_and_feeds_command_error(self):
        code, content, details = self._run_main(
            [fenced("old\nnew\n"), fenced("old\nnew\n")],
            task_overrides={"limits": self.task["limits"] | {"local_attempts": 2}},
            command_code=[1, 0], command_stderr="compiler: expected ';'",
            return_details=True,
        )
        self.assertEqual(code, 0)
        self.assertEqual(content, "old\nnew\n")
        self.assertEqual(details["summary"]["attempts"], 2)
        self.assertIn("compiler: expected ';'", details["prompts"][1])
        self.assertIn("Task commands did not pass.", details["prompts"][1])
        self.assertEqual(details["result"]["status"], "accepted")
        self.assertEqual(len(details["result"]["attempts"]), 2)

    def test_retry_starts_from_original_after_rollback(self):
        observed = []
        def request(prompt, model, endpoint, timeout):
            observed.append(target.read_text(encoding="utf-8"))
            return fenced("old\nnew\n"), {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "app.py"
            target.parent.mkdir()
            target.write_text("old\n", encoding="utf-8")
            task_path = root / "task.json"
            task = self.task | {"limits": self.task["limits"] | {"local_attempts": 2}}
            task_path.write_text(json.dumps(task), encoding="utf-8")
            config_path = root / "guardrails.json"
            config_path.write_text(json.dumps(self.config), encoding="utf-8")
            git_results = ["", "", "src/app.py\0", "diff\n", "", "", "src/app.py\0", "diff\n", ""]
            commands = [
                CompletedProcess([], 1, "", "failure"),
                CompletedProcess([], 0, "", ""),
            ]
            with mock.patch.object(executor, "request_ollama", side_effect=request), \
                    mock.patch.object(executor, "git_output", side_effect=git_results), \
                    mock.patch.object(executor, "controlled_run", side_effect=commands), \
                    mock.patch.object(executor, "write_result", return_value=(root / "r.json", root / "p.patch")), \
                    mock.patch("sys.argv", ["executor.py", "--task", str(task_path), "--worktree", str(root), "--guardrails", str(config_path)]), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = executor.main()
            self.assertEqual(code, 0)
            self.assertEqual(observed, ["old\n", "old\n"])

    def test_repair_loop_stops_at_local_attempts(self):
        code, content, details = self._run_main(
            ["not a marker response", "still invalid"],
            task_overrides={"limits": self.task["limits"] | {"local_attempts": 2}},
            return_details=True,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")
        self.assertEqual(len(details["prompts"]), 2)
        self.assertEqual(details["summary"]["attempts"], 2)
        self.assertEqual(details["result"]["status"], "revise")
        self.assertTrue(details["result"]["rolled_back"])

    def test_stdout_summary_points_to_unique_result_path(self):
        code, _, details = self._run_main(fenced("old\nnew\n"), return_details=True)
        self.assertEqual(code, 0)
        self.assertTrue(details["summary"]["result_path"].endswith(".json"))
        self.assertNotEqual(details["summary"]["result_path"], "results/main-test.json")
        self.assertEqual(details["summary"]["status"], "accepted")

    @mock.patch("executor.git_output")
    def test_changed_file_scope_rejection(self, git_output):
        git_output.side_effect = [
            " M src/app.py\0 M README.md\0", "src/app.py\0README.md\0",
            "diff --git a/src/app.py b/src/app.py\n", "",
        ]
        errors, _, changed = executor.validate_diff(
            self.worktree, ["src/app.py"], executor.controller.SECRET_PATTERNS
        )
        self.assertEqual(changed, ["src/app.py", "README.md"])
        self.assertTrue(any("outside task allowlist" in item for item in errors))

    @mock.patch("executor.git_output")
    def test_secret_addition_rejection(self, git_output):
        git_output.side_effect = [
            " M src/app.py\0", "src/app.py\0",
            "diff --git a/src/app.py b/src/app.py\n+api_key=abcdefghijk\n",
            "",
        ]
        errors, _, _ = executor.validate_diff(
            self.worktree, ["src/app.py"], executor.controller.SECRET_PATTERNS
        )
        self.assertIn("Secret-like content appears in added diff lines.", errors)

    def test_exact_command_validation_rejects_shell_syntax(self):
        self.assertEqual(executor.validate_command("python -m unittest"), [])
        self.assertTrue(executor.validate_command("python -m unittest | more"))

    def test_task_requires_one_file(self):
        invalid = dict(self.task)
        invalid["allowed_files"] = ["src/app.py", "src/other.py"]
        errors = executor.validate_executor_task(invalid, self.worktree, self.config)
        self.assertIn("Task must allow exactly one file.", errors)

    def _run_main(
        self, response, task_overrides=None, original="old\n", command_code=0,
        command_stdout="", command_stderr="", return_details=False,
        write_result_error=None,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "src" / "app.py"
            target.parent.mkdir()
            target.write_text(original, encoding="utf-8")
            task_path = root / "task.json"
            task = dict(self.task)
            task["task_id"] = "main-test"
            task.update(task_overrides or {})
            task_path.write_text(json.dumps(task), encoding="utf-8")
            config_path = root / "guardrails.json"
            config_path.write_text(json.dumps(self.config), encoding="utf-8")
            response_list = response if isinstance(response, list) else [response]
            git_results = [""] + [
                value for _ in response_list
                for value in ("", "src/app.py\0", "diff\n", "")
            ]
            command_codes = command_code if isinstance(command_code, list) else [command_code]
            command_runs = [
                CompletedProcess([], code, command_stdout, command_stderr)
                for code in command_codes
            ]
            stdout = io.StringIO()
            result_write_count = 0

            def write_result(run_id, result, diff):
                nonlocal result_write_count
                result_write_count += 1
                if write_result_error and result_write_count == 1:
                    raise RuntimeError(write_result_error)
                return root / f"{run_id}.json", root / f"{run_id}.patch"

            with mock.patch.object(
                        executor, "request_ollama",
                        side_effect=[(item, {}) for item in response_list]
                    ) as request, \
                    mock.patch.object(executor, "git_output", side_effect=git_results), \
                    mock.patch.object(
                        executor, "controlled_run", side_effect=command_runs,
                    ), \
                    mock.patch.object(
                        executor, "write_result", side_effect=write_result,
                    ) as write_result_mock, \
                    mock.patch("sys.argv", [
                        "executor.py", "--task", str(task_path),
                        "--worktree", str(root),
                        "--guardrails", str(config_path),
                    ]), \
                    contextlib.redirect_stdout(stdout):
                code = executor.main()
            details = {
                "prompts": [call.args[0] for call in request.call_args_list],
                "result": write_result_mock.call_args.args[1],
                "summary": json.loads(stdout.getvalue()),
            }
            outcome = (code, target.read_text(encoding="utf-8"))
            return (*outcome, details) if return_details else outcome

    def test_unfenced_response_rejected_and_does_not_mutate(self):
        code, content = self._run_main("here is the file: new\n")
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_secret_output_rejects_and_does_not_mutate(self):
        code, content = self._run_main(fenced("old\napi_key=abcdefghijk\n"))
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_successful_additive_apply(self):
        code, content = self._run_main(fenced("old\nnew\n"))
        self.assertEqual(code, 0)
        self.assertEqual(content, "old\nnew\n")

    def test_finish_result_failure_rolls_back_accepted_proposal(self):
        code, content, details = self._run_main(
            fenced("old\nnew\n"), return_details=True,
            write_result_error="result write failed",
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")
        self.assertTrue(details["result"]["rolled_back"])
        self.assertEqual(details["result"]["status"], "revise")

    def test_destructive_replacement_rejected(self):
        code, content = self._run_main(fenced("new\n"))
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_removed_definition_rejected(self):
        original = "def keep():\n    return 1\n"
        code, content = self._run_main(
            fenced("def other():\n    return 2\n"), original=original
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(content, original)

    def test_missing_required_marker_rejected(self):
        code, content = self._run_main(
            fenced("old\nnew\n"), task_overrides={"must_preserve": ["sentinel"]}
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_failed_command_rolls_back(self):
        code, content = self._run_main(fenced("old\nnew\n"), command_code=1)
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_append_mode_keeps_original_content(self):
        code, content = self._run_main(
            fenced("new\n"), task_overrides={"mode": "append"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(content, "old\nnew\n")

    def test_append_mode_rejects_empty_block(self):
        code, content = self._run_main(
            fenced("   \n"), task_overrides={"mode": "append"}
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_markdown_fence_accepted(self):
        code, content = self._run_main(
            "```python\nnew\n```", task_overrides={"mode": "append"}
        )
        self.assertEqual(code, 0)
        self.assertEqual(content, "old\nnew\n")

    def test_two_markdown_blocks_rejected(self):
        code, content = self._run_main("```\na\n```\n```\nb\n```")
        self.assertNotEqual(code, 0)
        self.assertEqual(content, "old\n")

    def test_append_inserts_before_main_guard(self):
        original = 'a = 1\n\n\nif __name__ == "__main__":\n    run()\n'
        code, content = self._run_main(
            fenced("def added():\n    return 2\n"),
            task_overrides={"mode": "append"},
            original=original,
        )
        self.assertEqual(code, 0)
        self.assertLess(content.index("def added"), content.index("__main__"))
        self.assertEqual(content.count("__main__"), 1)

    def test_append_allows_existing_secret_fixture(self):
        original = "api_key=abcdefghijk\n"
        code, content = self._run_main(
            fenced("new\n"), task_overrides={"mode": "append"}, original=original
        )
        self.assertEqual(code, 0)
        self.assertEqual(content, "api_key=abcdefghijk\nnew\n")
    def test_append_strips_trailing_duplicate_main_guard(self):
        original = 'a = 1\n\n\nif __name__ == "__main__":\n    unittest.main()\n'
        response = fenced('def added():\n    return 2\n\nif __name__ == "__main__":\n    unittest.main()\n')
        code, content = self._run_main(
            response, task_overrides={"mode": "append"}, original=original
        )
        self.assertEqual(code, 0)
        self.assertLess(content.index("def added"), content.index("__main__"))
        self.assertEqual(content.count("__main__"), 1)
    def test_append_rejects_duplicate_main_guard(self):
        original = 'a = 1\n\n\nif __name__ == "__main__":\n    run()\n'
        code, content = self._run_main(
            fenced('if __name__ == "__main__":\n    run()\n'),
            task_overrides={"mode": "append"},
            original=original,
        )
        self.assertNotEqual(code, 0)
        self.assertEqual(content, original)

    def test_invalid_mode_rejected(self):
        invalid = dict(self.task)
        invalid["mode"] = "rewrite"
        errors = executor.validate_executor_task(invalid, self.worktree, self.config)
        self.assertIn("Field 'mode' must be full_body or append.", errors)

    def test_line_budget_counts(self):
        added, deleted = executor.line_budget("a\nb\n", "a\nb\nc\n")
        self.assertEqual((added, deleted), (1, 0))
        added, deleted = executor.line_budget("a\nb\n", "a\n")
        self.assertEqual((added, deleted), (0, 1))

    def test_environment_key_allowlist(self):
        invalid = dict(self.task)
        invalid["environment"] = {"PATH": "src"}
        errors = executor.validate_executor_task(invalid, self.worktree, self.config)
        self.assertTrue(any("Environment key not allowed" in item for item in errors))

    def test_budget_ceiling_enforced(self):
        invalid = dict(self.task)
        invalid["max_deleted_lines"] = executor.CEILING_MAX_DELETED_LINES + 1
        errors = executor.validate_executor_task(invalid, self.worktree, self.config)
        self.assertTrue(any("exceeds executor ceiling" in item for item in errors))


class ContextFileValidationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.root, ignore_errors=True))
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("old\n", encoding="utf-8")
        (self.root / "include").mkdir()
        (self.root / "include" / "version.h").write_text("#define V 1\n", encoding="utf-8")
        self.task = {
            "type": "implementation_task", "task_id": "context-test",
            "objective": "Test context files.", "allowed_files": ["src/app.py"],
            "allowed_commands": ["python -m unittest discover -s tests -v"],
            "acceptance_criteria": ["Tests pass."], "risk": "low",
            "requires_human_approval": False,
            "limits": {"local_attempts": 1, "paid_reviews": 1, "changed_files": 1, "command_timeout_seconds": 30},
        }
        self.config = {
            "allowlisted_files": ["src/**"],
            "allowlisted_commands": ["python -m unittest discover -s tests -v"],
            "risk_levels": ["low", "medium", "high"],
            "task_limits": {"local_attempts": 3, "paid_reviews": 2, "changed_files": 5, "command_timeout_seconds": 300},
        }

    def errors_for(self, paths):
        task = self.task | {"context_files": paths}
        return executor.validate_executor_task(task, self.root, self.config)

    def test_context_list_is_bounded_and_string_only(self):
        self.assertTrue(any("at most 5" in e for e in self.errors_for(["include/version.h"] * 6)))
        self.assertTrue(any("non-empty string" in e for e in self.errors_for([4])))

    def test_context_rejects_traversal(self):
        self.assertTrue(any("relative and non-traversing" in e for e in self.errors_for(["../secret.txt"])))

    def test_context_rejects_missing_file(self):
        self.assertTrue(any("exist inside the worktree" in e for e in self.errors_for(["include/missing.h"])))

    def test_context_rejects_target_file(self):
        self.assertTrue(any("must not be an allowed target" in e for e in self.errors_for(["src/app.py"])))

    def test_context_rejects_size_over_20_kb(self):
        (self.root / "include" / "large.h").write_bytes(b"x" * (20 * 1024 + 1))
        self.assertTrue(any("20 KB total size cap" in e for e in self.errors_for(["include/large.h"])))

    def test_context_contract_rejects_oversize_before_read(self):
        large = self.root / "include" / "large.h"
        large.write_bytes(b"x" * (20 * 1024 + 1))
        with mock.patch.object(Path, "open", autospec=True) as open_file:
            errors = self.errors_for(["include/large.h"])
        self.assertTrue(any("20 KB total size cap" in error for error in errors))
        open_file.assert_not_called()

    def test_executor_context_rejects_oversize_before_read(self):
        large = self.root / "include" / "large.h"
        large.write_bytes(b"x" * (20 * 1024 + 1))
        task = self.task | {"context_files": ["include/large.h"]}
        with mock.patch.object(Path, "open", autospec=True) as open_file:
            with self.assertRaisesRegex(ValueError, "20 KB total size cap"):
                executor.read_context_files(task, self.root, [])
        open_file.assert_not_called()

    def test_context_rejects_secret(self):
        (self.root / "include" / "version.h").write_text("api_key=abcdefghijk", encoding="utf-8")
        self.assertTrue(any("Sensitive content detected in context" in e for e in self.errors_for(["include/version.h"])))

    def test_context_need_not_match_write_allowlist(self):
        self.assertFalse(self.errors_for(["include/version.h"]))
        task = self.task | {"context_files": ["include/version.h"]}
        self.assertFalse(executor.controller.validate_task_contract(
            task, self.root, self.config
        ))


class ControllerContractTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "allowlisted_files": ["tests/**"],
            "allowlisted_commands": ["python -m unittest discover -s tests -v"],
            "risk_levels": ["low", "medium", "high"],
            "task_limits": {
                "local_attempts": 3, "paid_reviews": 2,
                "changed_files": 5, "command_timeout_seconds": 300,
            },
        }

    def _valid_task(self):
        return {
            "type": "implementation_task",
            "task_id": "contract-test",
            "objective": "Test contract.",
            "allowed_files": ["tests/test_executor.py"],
            "allowed_commands": ["python -m unittest discover -s tests -v"],
            "acceptance_criteria": ["Tests pass."],
            "risk": "low",
            "requires_human_approval": False,
            "limits": {
                "local_attempts": 1, "paid_reviews": 1,
                "changed_files": 1, "command_timeout_seconds": 30,
            },
        }

    def test_optional_task_keys_are_not_unknown(self):
        task = self._valid_task()
        task.update({
            "mode": "append",
            "must_preserve": ["class ExecutorTests(unittest.TestCase):"],
            "max_changed_lines": 70,
            "max_deleted_lines": 0,
            "environment": {"PYTHONPATH": "src"},
        })
        errors = executor.controller.validate_task_contract(
            task, Path("D:/worktree"), self.config
        )
        self.assertFalse(any("Unknown task keys" in error for error in errors))

    def test_unexpected_task_key_is_rejected(self):
        task = self._valid_task()
        task["unexpected"] = True
        errors = executor.controller.validate_task_contract(
            task, Path("D:/worktree"), self.config
        )
        self.assertTrue(any("Unknown task keys: unexpected" in error for error in errors))


class PolicyProfileTests(unittest.TestCase):
    def _profile_file(self, data: dict) -> str:
        handle = tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False)
        with handle:
            json.dump(data, handle)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return handle.name

    def _varta_profile(self) -> dict:
        return {
            "repo_root": "D:/Pets/varta.cmoka",
            "allowlisted_files": ["README.md", "src/**", "tests/**", "scripts/**", ".github/**"],
            "allowlisted_commands": [
                "python -m unittest discover -s tests -v",
                "python -m compileall -q src tests",
                "bash -n scripts/bootstrap-host.sh",
            ],
            "risk_levels": ["low", "medium", "high"],
            "task_limits": {
                "local_attempts": 3,
                "paid_reviews": 2,
                "changed_files": 5,
                "command_timeout_seconds": 300,
            },
        }

    def test_legacy_guardrails_still_load(self):
        path = self._profile_file(self._varta_profile())
        config = executor.controller.load_config(path)
        self.assertNotIn("profile", config)
        self.assertIn("tests/**", config["allowlisted_files"])

    def test_palac_profile_in_shipped_guardrails(self):
        path = Path(executor.__file__).with_name("guardrails.json")
        config = executor.controller.load_config(path, "palac")
        self.assertEqual("D:/Pets/palac.cmoka", config["repo_root"])
        self.assertIn("tools/sanitize-har.ps1", config["allowlisted_files"])
        for command in config["allowlisted_commands"]:
            self.assertEqual([], executor.validate_command(command))
        protected = ["tools/git-hooks/pre-commit.ps1", ".agents/skills/x/SKILL.md", ".github/workflows/x.yml"]
        for rel_path in protected:
            self.assertFalse(any(fnmatch.fnmatch(rel_path, p) for p in config["allowlisted_files"]), rel_path)

    def test_varta_profile_loads_by_active_profile(self):
        path = self._profile_file({
            "active_profile": "varta",
            "profiles": {"varta": self._varta_profile()},
        })
        config = executor.controller.load_config(path)
        self.assertEqual("varta", config["profile"])
        self.assertIn("tests/**", config["allowlisted_files"])
        self.assertIn(
            "python -m unittest discover -s tests -v",
            config["allowlisted_commands"],
        )
        self.assertEqual(300, config["task_limits"]["command_timeout_seconds"])

    def test_explicit_profile_overrides_active_profile(self):
        path = self._profile_file({
            "active_profile": "other",
            "profiles": {
                "other": self._varta_profile(),
                "varta": self._varta_profile() | {"allowlisted_files": ["tests/**"]},
            },
        })
        config = executor.controller.load_config(path, "varta")
        self.assertEqual(["tests/**"], config["allowlisted_files"])

    def test_unknown_profile_fails_closed(self):
        path = self._profile_file({
            "active_profile": "varta",
            "profiles": {"varta": self._varta_profile()},
        })
        with self.assertRaisesRegex(ValueError, "Unknown policy profile"):
            executor.controller.load_config(path, "missing")

    def test_profile_rejects_unknown_top_level_keys(self):
        path = self._profile_file({
            "active_profile": "varta",
            "profiles": {"varta": self._varta_profile()},
            "allowlisted_files": ["**"],
        })
        with self.assertRaisesRegex(ValueError, "Unknown top-level"):
            executor.controller.load_config(path)

    def test_profile_rejects_unknown_profile_keys(self):
        profile = self._varta_profile() | {"extra": True}
        path = self._profile_file({
            "active_profile": "varta",
            "profiles": {"varta": profile},
        })
        with self.assertRaisesRegex(ValueError, "Unknown config keys"):
            executor.controller.load_config(path)


if __name__ == "__main__":
    unittest.main()
