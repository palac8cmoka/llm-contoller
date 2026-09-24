#!/usr/bin/env python3
"""Controlled executor for approved one-file implementation tasks."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

import controller


FORBIDDEN_COMMAND_CHARS = set("|&;<>`$(){}[]'\"\r\n")
FORBIDDEN_PATH_PARTS = {".git", ".github", "hooks"}
DEPENDENCY_FILES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "poetry.lock", "pyproject.toml", "Pipfile",
    "Pipfile.lock", "Gemfile", "Gemfile.lock", "go.mod", "go.sum",
    "Cargo.toml", "Cargo.lock",
}
METADATA_FILES = {
    ".editorconfig", ".gitattributes", ".gitignore", ".gitmodules",
}
MAX_BODY_BYTES = 1024 * 1024
# Strict default: additive edits only
DEFAULT_MAX_DELETED_LINES = 0
DEFAULT_MAX_CHANGED_LINES = 200
CEILING_MAX_DELETED_LINES = 40
CEILING_MAX_CHANGED_LINES = 400
ALLOWED_ENVIRONMENT_KEYS = {"PYTHONPATH"}
ENVIRONMENT_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*$")
BEGIN_MARKER = "<<<FILE>>>"
END_MARKER = "<<<END>>>"
TAIL_CONTEXT_LINES = 40
ALLOWED_MODES = {"full_body", "append"}


def tail_context(original: str) -> str:
    lines = original.splitlines()
    return "\n".join(lines[-TAIL_CONTEXT_LINES:])


MARKDOWN_FENCE_PATTERN = re.compile(r"```[A-Za-z0-9_+-]*\n(.*?)```", re.S)
MAIN_GUARD_PATTERN = re.compile(r"^if\s+__name__\s*==\s*[\"']__main__[\"']\s*:", re.M)


def compose_append(original: str, block: str) -> str:
    body = block.strip("\n")
    base = original if original.endswith("\n") else original + "\n"
    guard = MAIN_GUARD_PATTERN.search(base)
    if not guard:
        return base + body + "\n"
    head = base[:guard.start()].rstrip("\n")
    tail = base[guard.start():]
    return f"{head}\n\n\n{body}\n\n\n{tail}"


def extract_fenced_body(response: str) -> tuple[list[str], str | None]:
    if response.count(BEGIN_MARKER) != 1 or response.count(END_MARKER) != 1:
        blocks = MARKDOWN_FENCE_PATTERN.findall(response)
        if len(blocks) == 1:
            return [], blocks[0].replace("\r\n", "\n")
        return ["Response must contain exactly one fenced body."], None
    start = response.index(BEGIN_MARKER) + len(BEGIN_MARKER)
    end = response.index(END_MARKER)
    if end < start:
        return ["Response markers are out of order."], None
    body = response[start:end]
    if body.startswith("\r\n"):
        body = body[2:]
    elif body.startswith("\n"):
        body = body[1:]
    return [], body.replace("\r\n", "\n")


class ExecutorRejection(Exception):
    """Post-write rejection that must roll back the file."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return value


def relative_path(value: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid relative path: {value}")
    path = Path(value)
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError(f"Invalid relative path: {value}")
    return path


def validate_command(command: str) -> list[str]:
    if not isinstance(command, str) or not command or command != command.strip():
        return ["Command must be a non-empty trimmed string."]
    if any(char in command for char in FORBIDDEN_COMMAND_CHARS):
        return [f"Command contains forbidden shell syntax: {command}"]
    parts = command.split()
    if not parts or "=" in parts[0]:
        return [f"Command is not a direct executable invocation: {command}"]
    return []


def positive_budget(task: dict, name: str, default: int, ceiling: int) -> tuple[int, list[str]]:
    value = task.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return default, [f"Field '{name}' must be a non-negative integer."]
    if value > ceiling:
        return default, [f"Field '{name}' exceeds executor ceiling {ceiling}."]
    return value, []


def validate_environment(task: dict, worktree: Path) -> tuple[dict[str, str], list[str]]:
    environment = task.get("environment", {})
    if not isinstance(environment, dict):
        return {}, ["Field 'environment' must be an object."]
    errors: list[str] = []
    for key, value in environment.items():
        if key not in ALLOWED_ENVIRONMENT_KEYS:
            errors.append(f"Environment key not allowed: {key}")
            continue
        if not isinstance(value, str) or not ENVIRONMENT_VALUE_PATTERN.match(value):
            errors.append(f"Environment value not allowed: {key}")
            continue
        try:
            resolved = (worktree / value).resolve()
            resolved.relative_to(worktree.resolve())
        except (ValueError, OSError):
            errors.append(f"Environment value escapes worktree: {key}")
            continue
        if not resolved.is_dir():
            errors.append(f"Environment value must be an existing directory: {key}")
    return ({} if errors else {str(k): str(v) for k, v in environment.items()}), errors


def validate_executor_task(task: dict, worktree: Path, config: dict) -> list[str]:
    errors = controller.validate_task_contract(task, worktree, config)
    allowed_files = task.get("allowed_files")
    if not isinstance(allowed_files, list) or len(allowed_files) != 1:
        errors.append("Task must allow exactly one file.")
    if not task.get("allowed_commands"):
        errors.append("Task must allow at least one command.")
    for file_name in allowed_files if isinstance(allowed_files, list) else []:
        if isinstance(file_name, str):
            try:
                relative_path(file_name)
                if blocked_path(file_name):
                    errors.append(f"Blocked path: {file_name}")
            except ValueError as exc:
                errors.append(str(exc))
    for command in task.get("allowed_commands", []):
        if isinstance(command, str):
            errors.extend(validate_command(command))
    must_preserve = task.get("must_preserve", [])
    if not isinstance(must_preserve, list) or not all(
        isinstance(item, str) and item.strip() for item in must_preserve
    ):
        errors.append("Field 'must_preserve' must be a list of non-empty strings.")
    errors.extend(
        positive_budget(task, "max_deleted_lines", DEFAULT_MAX_DELETED_LINES, CEILING_MAX_DELETED_LINES)[1]
    )
    errors.extend(
        positive_budget(task, "max_changed_lines", DEFAULT_MAX_CHANGED_LINES, CEILING_MAX_CHANGED_LINES)[1]
    )
    errors.extend(validate_environment(task, worktree)[1])
    if task.get("mode", "full_body") not in ALLOWED_MODES:
        errors.append("Field 'mode' must be full_body or append.")
    return errors


def controlled_run(
    args: list[str],
    cwd: Path,
    timeout: int,
    input_text: str | None = None,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    env = None
    if environment:
        env = os.environ.copy()
        env.update(environment)
    return subprocess.run(
        args, cwd=cwd, input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, shell=False, check=False, env=env,
    )


def git_output(worktree: Path, args: list[str]) -> str:
    result = controlled_run(["git", *args], worktree, 30)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Git command failed.")
    return result.stdout


def ensure_clean_worktree(worktree: Path) -> list[str]:
    try:
        status = git_output(worktree, ["status", "--porcelain=v1", "-z"])
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return [f"Worktree check failed: {exc}"]
    if status:
        return ["Dedicated worktree must be clean before implementation."]
    return []


def blocked_path(path: str) -> bool:
    item = relative_path(path)
    return (
        item.name in DEPENDENCY_FILES
        or item.name in METADATA_FILES
        or any(part in FORBIDDEN_PATH_PARTS for part in item.parts)
    )


def validate_diff(
    worktree: Path, allowed_files: list[str], patterns: list[str]
) -> tuple[list[str], str, list[str]]:
    errors: list[str] = []
    try:
        status = git_output(worktree, ["status", "--porcelain=v1", "-z"])
        names = git_output(worktree, ["diff", "--name-only", "-z"])
        changed_files = [name for name in names.split("\0") if name]
        diff = git_output(
            worktree, ["diff", "--no-ext-diff", "--binary", "--", *allowed_files]
        )
        summary = git_output(worktree, ["diff", "--summary"])
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return [f"Diff collection failed: {exc}"], "", []

    for entry in (item for item in status.split("\0") if item):
        state, name = entry[:2], entry[3:]
        if state[0] != " ":
            errors.append(f"Staged changes are not allowed: {name}")
        if state == "??":
            errors.append(f"Untracked changes are not allowed: {name}")
    allowed = set(allowed_files)
    outside = sorted(set(changed_files) - allowed)
    if outside:
        errors.append(f"Changes outside task allowlist: {', '.join(outside)}")
    for changed in changed_files:
        try:
            if blocked_path(changed):
                errors.append(f"Blocked path changed: {changed}")
        except ValueError:
            errors.append(f"Invalid changed path: {changed}")
    if "GIT binary patch" in diff or "Binary files " in diff:
        errors.append("Binary changes are not allowed.")
    if "old mode " in diff or "new mode " in diff or " mode change " in summary:
        errors.append("Permission or special file mode changes are not allowed.")
    if " create mode 120000" in summary or " create mode 160000" in summary:
        errors.append("Symlink or submodule changes are not allowed.")

    added = "\n".join(
        line[1:] for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    if controller.sanitize_text(added, patterns) != added:
        errors.append("Secret-like content appears in added diff lines.")
    return errors, diff, changed_files


DEFINITION_PATTERN = re.compile(r"^\s*(?:async\s+)?(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)


def line_budget(original: str, proposed: str) -> tuple[int, int]:
    diff = difflib.unified_diff(
        original.splitlines(), proposed.splitlines(), lineterm="", n=0
    )
    added = deleted = 0
    for line in diff:
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            deleted += 1
    return added, deleted


def validate_preservation(task: dict, original: str, proposed: str) -> list[str]:
    errors: list[str] = []
    max_deleted, _ = positive_budget(
        task, "max_deleted_lines", DEFAULT_MAX_DELETED_LINES, CEILING_MAX_DELETED_LINES
    )
    max_changed, _ = positive_budget(
        task, "max_changed_lines", DEFAULT_MAX_CHANGED_LINES, CEILING_MAX_CHANGED_LINES
    )
    added, deleted = line_budget(original, proposed)
    if deleted > max_deleted:
        errors.append(f"Deleted {deleted} lines, budget is {max_deleted}.")
    if added + deleted > max_changed:
        errors.append(f"Changed {added + deleted} lines, budget is {max_changed}.")
    if not proposed.strip():
        errors.append("Proposed content is empty.")
    for marker in task.get("must_preserve", []):
        if marker not in proposed:
            errors.append(f"Required content missing: {marker}")
    if max_deleted == 0:
        lost = sorted(
            set(DEFINITION_PATTERN.findall(original)) - set(DEFINITION_PATTERN.findall(proposed))
        )
        if lost:
            errors.append(f"Existing definitions removed: {', '.join(lost)}")
    return errors


def implementation_prompt(task: dict, path: str, original: str) -> str:
    criteria = "\n".join(f"- {item}" for item in task["acceptance_criteria"])
    if task.get("mode") == "append":
        return (
            "Write only new code to append to the end of one file.\n"
            f"File: {path}\n"
            f"Objective: {task['objective']}\n"
            "Acceptance criteria:\n"
            f"{criteria}\n"
            "End of the current file:\n"
            f"{tail_context(original)}\n"
            "Rules: output only the new lines. Do not repeat existing code. "
            "Do not output imports. Keep the same indentation as the "
            "surrounding code.\n"
            "Answer in exactly this format, with nothing before or after:\n"
            f"{BEGIN_MARKER}\n<new lines>\n{END_MARKER}"
        )
    return (
        "Implement the approved task in exactly one file.\n"
        f"File: {path}\n"
        f"Objective: {task['objective']}\n"
        "Acceptance criteria:\n"
        f"{criteria}\n"
        "Current file content:\n"
        f"{original}\n"
        "Rules: output the complete file, keep every existing line, "
        "function, class, and test unchanged, and only add what the "
        "objective asks. Never delete or rewrite existing code.\n"
        "Answer in exactly this format, with nothing before or after:\n"
        f"{BEGIN_MARKER}\n<complete file content>\n{END_MARKER}"
    )


def request_ollama(
    prompt: str, model: str, endpoint: str, timeout: int | None
) -> tuple[str, dict]:
    body = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Ollama request failed: {exc}") from exc
    answer = payload.get("response")
    if not isinstance(answer, str):
        raise RuntimeError("Ollama returned no text response.")
    metrics = {
        "model": model,
        "prompt_eval_count": payload.get("prompt_eval_count"),
        "eval_count": payload.get("eval_count"),
        "total_duration_ns": payload.get("total_duration"),
        "load_duration_ns": payload.get("load_duration"),
    }
    return answer, metrics


def validate_body_response(
    response: str,
    allowed_path: str,
    patterns: list[str],
    worktree: Path,
    original: str = "",
    mode: str = "full_body",
) -> tuple[list[str], str | None]:
    errors, body = extract_fenced_body(response)
    if errors or body is None:
        return errors, None
    try:
        rel = relative_path(allowed_path)
    except ValueError as exc:
        return [str(exc)], None
    if blocked_path(allowed_path):
        return ["Task targets a blocked path."], None
    lexical_target = worktree / rel
    current = worktree
    for part in rel.parts:
        current = current / part
        if current.is_symlink():
            return ["Target path contains a symlink."], None
    target = lexical_target.resolve()
    try:
        target.relative_to(worktree.resolve())
    except ValueError:
        return ["Task path escapes worktree."], None
    if target.is_symlink() or not target.is_file():
        return ["Target must be an existing regular non-symlink file."], None
    if mode == "append":
        if not body.strip():
            return ["Appended block is empty."], None
        if MAIN_GUARD_PATTERN.search(body) and MAIN_GUARD_PATTERN.search(original):
            return ["Appended block repeats the module entry guard."], None
        content = compose_append(original, body)
    else:
        content = body
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        return [f"Ollama response content is not valid UTF-8: {exc}"], None
    if b"\0" in encoded:
        return ["Ollama response content contains NUL."], None
    if len(encoded) > MAX_BODY_BYTES:
        return ["Ollama response content exceeds size cap."], None
    if controller.sanitize_text(content, patterns) != content:
        return ["Secret-like content appears in proposed content."], None
    return [], content


def atomic_write(target: Path, content: str) -> None:
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=target.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_result(task_id: str, result: dict, diff: str) -> tuple[Path, Path]:
    base = Path(__file__).resolve().parent
    results, patches = base / "results", base / "patches"
    results.mkdir(exist_ok=True)
    patches.mkdir(exist_ok=True)
    safe_id = "".join(char if char.isalnum() or char in "-_" else "_" for char in task_id)
    diff_path, result_path = patches / f"{safe_id}.patch", results / f"{safe_id}.json"
    diff_path.write_text(diff, encoding="utf-8")
    result["diff_path"] = str(diff_path)
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result_path, diff_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Controlled one-file executor.")
    parser.add_argument("--task", required=True, type=Path)
    parser.add_argument("--worktree", required=True, type=Path)
    parser.add_argument("--guardrails", type=Path)
    parser.add_argument("--model", default="qwen2.5-coder:7b")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    # Wait while model alive, no kill
    parser.add_argument("--generation-timeout", type=int, default=None)
    args = parser.parse_args()

    result = {
        "status": "blocked",
        "changed_files": [],
        "validation_errors": [],
        "commands": [],
        "rolled_back": False,
        "ollama": {},
    }
    diff = ""
    try:
        worktree = args.worktree.resolve(strict=True)
        if not worktree.is_dir():
            raise ValueError("Worktree path must be a directory.")
        task = load_json(args.task)
        config = controller.load_config(args.guardrails)
        errors = validate_executor_task(task, worktree, config)
        errors.extend(ensure_clean_worktree(worktree))
        if errors:
            result["validation_errors"] = errors
            write_result(str(task.get("task_id", "invalid-task")), result, "Validation failed.\n")
            return 1

        allowed_path = task["allowed_files"][0]
        lexical_target = worktree / relative_path(allowed_path)
        target = lexical_target.resolve()
        try:
            target.relative_to(worktree.resolve())
        except ValueError as exc:
            raise ValueError("Allowed target path escapes worktree.") from exc
        if any(
            current.is_symlink()
            for current in (
                worktree.joinpath(*relative_path(allowed_path).parts[:index])
                for index in range(1, len(relative_path(allowed_path).parts) + 1)
            )
        ):
            raise ValueError("Allowed target path contains a symlink.")
        if not target.is_file():
            raise ValueError("Allowed target must be an existing regular non-symlink file.")
        original = target.read_text(encoding="utf-8")
        environment, _ = validate_environment(task, worktree)
        response, metrics = request_ollama(
            implementation_prompt(task, allowed_path, original),
            args.model, args.endpoint, args.generation_timeout,
        )
        result["ollama"] = metrics
        patterns = config.get("secret_patterns", controller.SECRET_PATTERNS)
        errors, proposed = validate_body_response(
            response, allowed_path, patterns, worktree,
            original, task.get("mode", "full_body"),
        )
        if errors:
            result["status"] = "revise"
            result["validation_errors"] = errors
            write_result(task["task_id"], result, "Validation failed.\n" + response)
            return 1
        errors = validate_preservation(task, original, proposed)
        preview = f"Original content:\n{original}\n\nProposed content:\n{proposed}"
        if errors:
            result["status"] = "revise"
            result["validation_errors"] = errors
            write_result(task["task_id"], result, preview)
            return 1
        write_result(task["task_id"], result, preview)
        atomic_write(target, proposed)
        try:
            errors, diff, changed = validate_diff(worktree, [allowed_path], patterns)
            result["changed_files"] = changed
            if errors:
                raise ExecutorRejection(errors)
            result["commands"] = run_task_commands(
                task["allowed_commands"], worktree,
                task["limits"]["command_timeout_seconds"], environment,
            )
            if any(item.get("exit_code") != 0 for item in result["commands"]):
                raise ExecutorRejection(["Task commands did not pass."])
        except (ExecutorRejection, OSError, ValueError, RuntimeError) as exc:
            atomic_write(target, original)
            result["status"] = "revise"
            result["rolled_back"] = True
            result["validation_errors"] = (
                exc.errors if isinstance(exc, ExecutorRejection) else [str(exc)]
            )
            write_result(task["task_id"], result, preview + "\n\n" + diff)
            return 1
        result["status"] = "accepted"
        write_result(task["task_id"], result, preview + "\n\n" + diff)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        result["validation_errors"] = [str(exc)]
        write_result("executor-error", result, diff)
        return 1


def run_task_commands(
    commands: list[str],
    worktree: Path,
    timeout: int,
    environment: dict[str, str] | None = None,
) -> list[dict]:
    results = []
    for command in commands:
        errors = validate_command(command)
        if errors:
            results.append({"command": command, "exit_code": None, "error": errors[0]})
            continue
        try:
            result = controlled_run(command.split(), worktree, timeout, None, environment)
            results.append({
                "command": command, "exit_code": result.returncode,
                "stdout": result.stdout[-4000:], "stderr": result.stderr[-4000:],
            })
        except subprocess.TimeoutExpired:
            results.append({"command": command, "exit_code": None, "error": "Command timed out."})
    return results


if __name__ == "__main__":
    raise SystemExit(main())
