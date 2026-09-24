# Security Policy

## Supported versions

This repository does not publish versioned releases yet. Security fixes target
the default branch only.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Tags or old commits | No |

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available.
If that is unavailable, open a GitHub issue with a minimal description and do
not include exploit details, credentials, tokens, private logs, or customer
data.

For reports, include:

- affected file or command;
- impact and preconditions;
- safe reproduction steps without secrets;
- suggested fix, if known.

Expect triage on a best-effort basis. Accepted fixes are handled as normal pull
requests unless disclosure timing requires a private advisory.

## Scope

In scope:

- controller validation bypasses;
- unsafe file writes or command execution;
- secret exposure in prompts, diffs, logs, or artifacts;
- GitHub Actions or repository policy regressions.

Out of scope:

- denial-of-service against local development machines;
- findings that require already having arbitrary local code execution;
- placeholder sample values that are not real credentials.

## Handling rules

Do not commit real secrets, exploit payloads, private keys, or token material.
Use minimal redacted examples. Keep reports focused on this repository.
