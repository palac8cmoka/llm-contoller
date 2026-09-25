# Shared LLM controller

This directory sits one level above the project repo and acts as the enforcement boundary for paid-LLM orchestration.

## Purpose

- keep the paid LLM read-only and sanitized
- reject malformed task contracts
- block secrets, out-of-scope file access, and unapproved commands
- keep all policy logic in one place for both the local controller and project agents

## Files

- `controller.py` — validation and redaction CLI
- `executor.py` — opt-in local implementation executor
- `guardrails.json` — allowlists and policy configuration

## Basic usage

Validate a request payload before sending it to a paid model:

```powershell
python D:\Pets\llm-controller\controller.py validate-request --input D:\temp\llm-request.json --repo-root D:\Pets\varta.cmoka --guardrails D:\Pets\llm-controller\guardrails.json
```

Validate a paid-model task response before executing anything locally:

```powershell
python D:\Pets\llm-controller\controller.py validate-response --input D:\temp\llm-task.json --repo-root D:\Pets\varta.cmoka --guardrails D:\Pets\llm-controller\guardrails.json
```

Redact secrets from text:

```powershell
python D:\Pets\llm-controller\controller.py sanitize --text "API key=abc123" --guardrails D:\Pets\llm-controller\guardrails.json
```

Ask Ollama for a task contract through the same validation gate:

```powershell
python D:\Pets\llm-controller\controller.py ollama-task --input D:\Pets\llm-controller\request.json --repo-root D:\Pets\varta.cmoka --guardrails D:\Pets\llm-controller\guardrails.json --model qwen2.5-coder:7b
```

Retry once with a stronger local model if the first response fails contract
validation:

```powershell
python D:\Pets\llm-controller\controller.py ollama-task --input D:\Pets\llm-controller\request.json --repo-root D:\Pets\varta.cmoka --guardrails D:\Pets\llm-controller\guardrails.json --model qwen2.5-coder:7b --fallback-model qwen2.5-coder:14b
```

The bridge validates the request before sending it, requires JSON from Ollama,
then validates the returned task before printing it. It never executes returned
commands or edits repository files.

## Policy profiles

`guardrails.json` may define named policy profiles. The active profile is
selected by `active_profile`, or explicitly with `--profile`. Profiles are
standalone policy objects; unknown profile names and unknown profile keys fail
closed.

The included `varta` profile preserves the current Varta Cmoka file, command,
risk, secret, and limit policy.

```powershell
python D:\Pets\llm-controller\controller.py validate-response --input D:\temp\llm-task.json --guardrails D:\Pets\llm-controller\guardrails.json --profile varta
```

## Policy rules

The controller fails closed on:

- missing task keys
- malformed JSON
- secret exposure
- file paths outside the repo root
- commands not in the allowlist
- files not in the allowlist
- high-risk tasks without human approval
- task limits outside controller policy
- unknown task or limit fields

## Required contract

A paid-model reply must match this shape:

```json
{
  "type": "implementation_task",
  "task_id": "validate-xml-config",
  "objective": "Validate required XML configuration fields.",
  "allowed_files": ["src/config.py", "tests/test_config.py"],
  "allowed_commands": ["python -m pytest tests/test_config.py"],
  "acceptance_criteria": [
    "Missing required fields produce a clear error.",
    "Existing valid configurations continue to work.",
    "The targeted tests pass."
  ],
  "risk": "low",
  "requires_human_approval": false,
  "limits": {
    "local_attempts": 3,
    "paid_reviews": 2,
    "changed_files": 5,
    "command_timeout_seconds": 300
  }
}
```

This is the minimum safe contract for a local agent to proceed.

## Minimal executor

`executor.py` accepts an approved task contract with exactly one existing
allowed file in a clean dedicated worktree. It asks local Ollama
`/api/generate` for one JSON object containing that exact path and complete
file body. It validates the body before an atomic write, including path,
regular-file, UTF-8, size, NUL, secret, dependency, Git metadata, hook, and
symlink checks. It then validates the Git diff and runs only exact
task-listed commands with `shell=False`. Results and previews are saved under
`results/` and `patches/`.

Before writing, it enforces content preservation. The model body is rejected
when it deletes more than `max_deleted_lines` (default `0`), changes more than
`max_changed_lines` (default `200`), is empty, drops a string listed in
`must_preserve`, or removes an existing `def`/`class` name while the deletion
budget is zero. Budgets are capped by executor ceilings. After writing, any
diff failure, command failure, or error restores the original file and reports
`status: revise` with `rolled_back: true`. Ollama prompt and output token
counts are stored in the result JSON.

Tasks may set `environment` with allowlisted keys only (currently
`PYTHONPATH`). Values must be simple relative paths that resolve to existing
directories inside the worktree, so tests can run without shell syntax.

The model answers with one fenced body, either the `<<<FILE>>>`/`<<<END>>>`
markers or a single markdown code block. Task `mode` selects `full_body`
(default) or `append`. In `append` mode the model writes only new lines, the
original file is preserved by construction, the block is inserted before the
module entry guard when one exists, and a repeated entry guard is rejected.
Generation has no timeout by default, so a live local model is never killed;
`--generation-timeout` can set one explicitly.

```powershell
python D:\Pets\llm-controller\executor.py --task D:\tasks\approved.json --worktree D:\worktrees\dedicated --guardrails D:\Pets\llm-controller\guardrails.json
```

No implementation hook or arbitrary implementation command exists. The
executor never executes commands returned by Ollama and never commits, pushes,
merges, deploys, installs dependencies, or uses non-localhost network access.
