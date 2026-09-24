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

    def _run_main(self, response, task_overrides=None, original="old\n", command_code=0):
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
            git_results = ["", "", "src/app.py\0", "diff\n", ""]
            with mock.patch.object(
                        executor, "request_ollama", return_value=(response, {})
                    ), \
                    mock.patch.object(executor, "git_output", side_effect=git_results), \
                    mock.patch.object(
                        executor, "controlled_run",
                        return_value=CompletedProcess([], command_code, "", ""),
                    ), \
                    mock.patch.object(executor, "write_result"), \
                    mock.patch("sys.argv", [
                        "executor.py", "--task", str(task_path),
                        "--worktree", str(root),
                        "--guardrails", str(config_path),
                    ]):
                code = executor.main()
            return code, target.read_text(encoding="utf-8")

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
