#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REQUIRED_TASK_FIELDS = {
    "type",
    "task_id",
    "objective",
    "allowed_files",
    "allowed_commands",
    "acceptance_criteria",
    "risk",
    "requires_human_approval",
    "limits",
}

# Executor-only keys, validated by executor
OPTIONAL_TASK_FIELDS = {
    "must_preserve",
    "max_changed_lines",
    "max_deleted_lines",
    "environment",
    "mode",
}

REQUIRED_LIMIT_FIELDS = {
    "local_attempts",
    "paid_reviews",
    "changed_files",
    "command_timeout_seconds",
}
SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|token|secret|password|passwd|private[_-]?key)[^\n\r]{0,30}[:=][ \t]*[A-Za-z0-9_\-./+=]{8,}",
    r"(?i)sk-[A-Za-z0-9]{16,}",
    r"(?i)(ghp|github_pat|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}",
    r"(?i)(AKIA|ASIA)[A-Z0-9]{12,}",
    r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)aws_access_key_id|aws_secret_access_key",
]


def load_config(path: str | Path | None) -> dict[str, Any]:
    cfg_path = Path(path) if path else Path(__file__).with_name("guardrails.json")
    if not cfg_path.exists():
        return {
            "repo_root": str(Path("D:/Pets/varta.cmoka").resolve()),
            "allowlisted_commands": [],
            "allowlisted_files": [],
            "secret_patterns": SECRET_PATTERNS,
            "risk_levels": ["low", "medium", "high"],
            "task_limits": {
                "local_attempts": 3,
                "paid_reviews": 2,
                "changed_files": 5,
                "command_timeout_seconds": 300,
            },
        }
    with cfg_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("repo_root", str(Path("D:/Pets/varta.cmoka").resolve()))
    data.setdefault("allowlisted_commands", [])
    data.setdefault("allowlisted_files", [])
    data.setdefault("secret_patterns", SECRET_PATTERNS)
    data.setdefault("risk_levels", ["low", "medium", "high"])
    data.setdefault(
        "task_limits",
        {
            "local_attempts": 3,
            "paid_reviews": 2,
            "changed_files": 5,
            "command_timeout_seconds": 300,
        },
    )
    return data


def redact_secrets(value: Any, patterns: list[str] | None = None) -> Any:
    if value is None:
        return value
    if isinstance(value, (dict, list)):
        return value
    text = str(value)
    for pattern in patterns or SECRET_PATTERNS:
        text = re.sub(pattern, "[REDACTED]", text, flags=re.IGNORECASE)
    return text


def normalize_repo_root(repo_root: str | Path) -> Path:
    return Path(repo_root).expanduser().resolve()


def sanitize_text(text: str, patterns: list[str] | None = None) -> str:
    redacted = text
    for pattern in patterns or SECRET_PATTERNS:
        redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


def ensure_within_repo(path_value: str, repo_root: Path) -> None:
    target = Path(path_value).expanduser()
    if not target.is_absolute():
        target = (repo_root / target).resolve()
    else:
        target = target.resolve()
    try:
        target.relative_to(repo_root)
    except ValueError as exc:
        raise ValueError(f"Path escapes repo root: {path_value}") from exc


def validate_request_payload(payload: dict[str, Any], repo_root: Path, config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {"project", "goal", "language", "relevant_files", "git_diff"}
    missing = sorted(required - set(payload))
    if missing:
        errors.append(f"Missing request keys: {', '.join(missing)}")

    for field in ("project", "goal"):
        if field in payload and not isinstance(payload[field], str):
            errors.append(f"Field '{field}' must be a string.")

    relevant_files = payload.get("relevant_files", {})
    if not isinstance(relevant_files, dict):
        errors.append("Field 'relevant_files' must be a dictionary.")
    else:
        for rel_path, value in relevant_files.items():
            try:
                ensure_within_repo(str(rel_path), repo_root)
            except ValueError as exc:
                errors.append(str(exc))
            if isinstance(value, str):
                if sanitize_text(value, config.get("secret_patterns")) != value:
                    errors.append(f"Sensitive content detected in relevant file '{rel_path}'.")

    for key in ("test_output", "git_diff"):
        value = payload.get(key, "")
        if isinstance(value, str) and sanitize_text(value, config.get("secret_patterns")) != value:
            errors.append(f"Sensitive content detected in '{key}'.")

    return errors


def validate_task_contract(task: dict[str, Any], repo_root: Path, config: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = sorted(REQUIRED_TASK_FIELDS - set(task))
    if missing:
        errors.append(f"Missing task keys: {', '.join(missing)}")
    unknown = sorted(set(task) - REQUIRED_TASK_FIELDS - OPTIONAL_TASK_FIELDS)
    if unknown:
        errors.append(f"Unknown task keys: {', '.join(unknown)}")

    if task.get("risk") not in set(config.get("risk_levels", ["low", "medium", "high"])):
        errors.append("Field 'risk' must be low, medium, or high.")

    if not isinstance(task.get("requires_human_approval"), bool):
        errors.append("Field 'requires_human_approval' must be true or false.")

    for field in ("type", "task_id", "objective"):
        if not isinstance(task.get(field), str) or not task[field].strip():
            errors.append(f"Field '{field}' must be a non-empty string.")

    if not isinstance(task.get("allowed_files"), list):
        errors.append("Field 'allowed_files' must be a list.")
    else:
        file_allowlist = config.get("allowlisted_files", [])
        for rel_path in task["allowed_files"]:
            if not isinstance(rel_path, str) or not rel_path:
                errors.append("Each allowed file must be a non-empty string.")
                continue
            path = Path(rel_path)
            if path.is_absolute() or ".." in path.parts:
                errors.append(f"File path must be relative and non-traversing: {rel_path}")
                continue
            try:
                ensure_within_repo(rel_path, repo_root)
            except ValueError as exc:
                errors.append(str(exc))
                continue
            if not any(fnmatch.fnmatch(rel_path, pattern) for pattern in file_allowlist):
                errors.append(f"File not allowlisted: {rel_path}")

    if not isinstance(task.get("allowed_commands"), list):
        errors.append("Field 'allowed_commands' must be a list.")
    else:
        allowed_commands = config.get("allowlisted_commands", [])
        for command in task["allowed_commands"]:
            if not isinstance(command, str):
                errors.append("Each allowed command must be a string.")
                continue
            if command not in allowed_commands:
                errors.append(f"Command not allowlisted: {command}")

    criteria = task.get("acceptance_criteria")
    if not isinstance(criteria, list) or not criteria:
        errors.append("Field 'acceptance_criteria' must be a non-empty list.")
    elif not all(isinstance(item, str) and item.strip() for item in criteria):
        errors.append("Each acceptance criterion must be a non-empty string.")

    limits = task.get("limits")
    if not isinstance(limits, dict):
        errors.append("Field 'limits' must be an object.")
    else:
        missing_limits = sorted(REQUIRED_LIMIT_FIELDS - set(limits))
        unknown_limits = sorted(set(limits) - REQUIRED_LIMIT_FIELDS)
        if missing_limits:
            errors.append(f"Missing limits keys: {', '.join(missing_limits)}")
        if unknown_limits:
            errors.append(f"Unknown limits keys: {', '.join(unknown_limits)}")
        max_limits = config.get("task_limits", {})
        for name in REQUIRED_LIMIT_FIELDS:
            value = limits.get(name)
            maximum = max_limits.get(name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                errors.append(f"Limit '{name}' must be a positive integer.")
            elif not isinstance(maximum, int) or value > maximum:
                errors.append(f"Limit '{name}' exceeds controller policy.")

    if task.get("requires_human_approval") is False and task.get("risk") == "high":
        errors.append("High-risk tasks must require human approval.")

    return errors


def validate_template() -> dict[str, Any]:
    return {
        "type": "implementation_task",
        "task_id": "validate-xml-config",
        "objective": "Validate required XML configuration fields.",
        "allowed_files": ["src/config.py", "tests/test_config.py"],
        "allowed_commands": ["python -m pytest tests/test_config.py"],
        "acceptance_criteria": [
            "Missing required fields produce a clear error.",
            "Existing valid configurations continue to work.",
            "The targeted tests pass.",
        ],
        "risk": "low",
        "requires_human_approval": False,
        "limits": {
            "local_attempts": 3,
            "paid_reviews": 2,
            "changed_files": 5,
            "command_timeout_seconds": 300,
        },
    }


def build_ollama_prompt(payload: dict[str, Any], config: dict[str, Any]) -> str:
    return (
        "You are a local implementation planner. Return only one JSON object. "
        "Do not use markdown fences or add commentary. "
        "Use only files and commands present in the supplied project context. "
        "The JSON must contain exactly these required fields, with arrays where shown: "
        "type, task_id, objective, allowed_files, allowed_commands, "
        "acceptance_criteria, risk, requires_human_approval, limits. "
        "risk must be exactly low, medium, or high. "
        "requires_human_approval must be true or false. "
        "Example shape: "
        '{"type":"implementation_task","task_id":"inspect-config",'
        '"objective":"Inspect configuration.","allowed_files":["README.md"],'
        '"allowed_commands":["git status --short"],'
        '"acceptance_criteria":["Return a clear result."],'
        '"risk":"low","requires_human_approval":false,'
        '"limits":{"local_attempts":3,"paid_reviews":2,'
        '"changed_files":5,"command_timeout_seconds":300}}.\n\n'
        f"Allowed files: {json.dumps(config.get('allowlisted_files', []))}\n"
        f"Allowed commands: {json.dumps(config.get('allowlisted_commands', []))}\n\n"
        f"Maximum limits: {json.dumps(config.get('task_limits', {}))}\n\n"
        f"Project context:\n{json.dumps(payload, ensure_ascii=True, indent=2)}"
    )


def call_ollama(
    prompt: str,
    model: str,
    endpoint: str,
    timeout_seconds: int,
) -> str:
    request_body = json.dumps(
        {"model": model, "prompt": prompt, "stream": False, "format": "json"}
    ).encode("utf-8")
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/api/generate",
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            response_body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Ollama request failed: {exc}") from exc

    result = response_body.get("response")
    if not isinstance(result, str) or not result.strip():
        raise RuntimeError("Ollama returned no response text.")
    return result


def parse_model_json(response_text: str) -> dict[str, Any]:
    cleaned = response_text.strip()
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", cleaned, flags=re.IGNORECASE)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ollama response is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Ollama response must be a JSON object.")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Shared LLM controller with failing-closed policy enforcement.")
    parser.add_argument(
        "command",
        choices=["validate-request", "validate-response", "sanitize", "sample-task", "ollama-task"],
        help="Controller action to run.",
    )
    parser.add_argument("--input", help="Path to JSON input file or '-' for stdin.")
    parser.add_argument("--repo-root", default=str(Path("D:/Pets/varta.cmoka").resolve()), help="Repository root to enforce.")
    parser.add_argument("--guardrails", help="Path to JSON guardrails file.")
    parser.add_argument("--text", help="Raw text to redact.")
    parser.add_argument("--model", default="qwen2.5-coder:7b", help="Ollama model name.")
    parser.add_argument("--fallback-model", help="Retry once with this stronger Ollama model after contract rejection.")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434", help="Ollama base URL.")
    parser.add_argument("--timeout", type=int, default=300, help="Ollama request timeout in seconds.")
    args = parser.parse_args()

    config = load_config(args.guardrails)
    repo_root = normalize_repo_root(args.repo_root or config.get("repo_root"))

    if args.command == "sample-task":
        print(json.dumps(validate_template(), indent=2))
        return 0

    if args.command == "sanitize":
        sample = args.text or sys.stdin.read()
        print(sanitize_text(sample, config.get("secret_patterns")))
        return 0

    if not args.input:
        print("Input file required for request/response validation.", file=sys.stderr)
        return 2

    if args.input == "-":
        payload_text = sys.stdin.read()
    else:
        with Path(args.input).open("r", encoding="utf-8") as fh:
            payload_text = fh.read()

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {exc}", file=sys.stderr)
        return 1

    if not isinstance(payload, dict):
        print("Input JSON must be an object.", file=sys.stderr)
        return 1

    if args.command == "ollama-task":
        request_errors = validate_request_payload(payload, repo_root, config)
        if request_errors:
            print("REQUEST VALIDATION FAILED", file=sys.stderr)
            for error in request_errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        models = [args.model]
        if args.fallback_model and args.fallback_model != args.model:
            models.append(args.fallback_model)
        last_errors: list[str] = []
        for model in models:
            try:
                response_text = call_ollama(
                    build_ollama_prompt(payload, config),
                    model,
                    args.endpoint,
                    args.timeout,
                )
                task = parse_model_json(response_text)
            except RuntimeError as exc:
                last_errors = [str(exc)]
                continue
            response_errors = validate_task_contract(task, repo_root, config)
            if not response_errors:
                print(json.dumps(task, indent=2))
                return 0
            last_errors = response_errors
        print("OLLAMA TASK FAILED", file=sys.stderr)
        for error in last_errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if args.command == "validate-request":
        errors = validate_request_payload(payload, repo_root, config)
        if errors:
            print("REQUEST VALIDATION FAILED", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("REQUEST VALIDATION OK")
        return 0

    if args.command == "validate-response":
        errors = validate_task_contract(payload, repo_root, config)
        if errors:
            print("RESPONSE VALIDATION FAILED", file=sys.stderr)
            for error in errors:
                print(f"- {error}", file=sys.stderr)
            return 1
        print("RESPONSE VALIDATION OK")
        return 0

    print("Unsupported command.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
