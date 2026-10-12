# agent-gate

An [Open Policy Agent](https://www.openpolicyagent.org/) gate for coding
agents. It runs as a Claude Code `PreToolUse` hook, hands every tool call to a
Rego policy and either logs the verdict (`observe`) or blocks the call
(`enforce`).

## Why

I explicitly allowed my coding agent to reset a workspace. It refused: the boundary lives in a policy file, not in the conversation.

That is the idea in one sentence. Instructions in a prompt can be argued with,
forgotten or overridden by the next message. A policy file is versioned,
reviewed and tested like code, and it answers the same way every time. If a
boundary should move, you change the file, not the conversation.

## How it works

```
Claude Code ── PreToolUse JSON ──> python -m agent_gate ── input ──> opa eval
                                          │                          │
                     exit 0 / exit 2  <───┴──── allow / deny ────────┘
                                          │
                                          └──> agent-gate.log.jsonl
```

1. Claude Code sends the `PreToolUse` document on stdin.
2. agent-gate builds a small input document:
   `{"tool", "command", "file_path", "cwd", "role"}`.
3. It runs `opa eval` against the policy directory and reads
   `data.agent_gate.decision`, which is `{"allow": bool, "violations": [...]}`.
4. It writes one JSON line per verdict to the log and returns an exit code.

agent-gate itself uses only the Python standard library (3.9 or newer). It needs
the `opa` binary.

## Installation

1. Install OPA: <https://www.openpolicyagent.org/docs/latest/#running-opa>
   (a single static binary).
2. Copy this directory somewhere stable, for example `/opt/agent-gate`.
3. Check the policy: `opa test /opt/agent-gate/policy -v`
4. Add the hook to `.claude/settings.json` of your project (or to your user
   settings). `examples/claude-settings.json` contains a complete entry:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [
          {"type": "command", "command": "PYTHONPATH=/opt/agent-gate python3 -m agent_gate"}
        ]
      }
    ]
  }
}
```

5. Try it by hand:

```sh
echo '{"tool_name": "Bash", "tool_input": {"command": "git reset --hard"}, "cwd": "/tmp"}' \
  | AGENT_GATE_MODE=enforce AGENT_GATE_POLICY_DIR=policy python3 -m agent_gate
echo "exit code: $?"
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AGENT_GATE_MODE` | `observe` | `observe` or `enforce` |
| `AGENT_GATE_ROLE` | `default` | role of the session, passed to the policy as `input.role` |
| `AGENT_GATE_OPA` | `opa` in `PATH` | path to the opa binary |
| `AGENT_GATE_POLICY_DIR` | `./policy` | directory with `.rego` files and `data.json` |
| `AGENT_GATE_LOG` | `./agent-gate.log.jsonl` | log file, one JSON line per verdict |

## The two modes

**observe** (default): every verdict is logged, nothing is blocked, the exit
code is always 0. Start here. Run your agent for a few days and read the log to
see what the policy would have blocked.

**enforce**: on deny the reason goes to stderr and the exit code is 2. Claude
Code then refuses the tool call and shows the reason to the agent.

If the gate itself fails (opa missing, a broken policy, invalid JSON on stdin),
observe fails open and enforce fails closed. Both write a log line with the
rule `GATE_ERROR` and the error message.

A log line looks like this:

```json
{"decision": "deny", "mode": "enforce", "reasons": ["DESTRUCTIVE: git reset --hard discards uncommitted work"], "role": "default", "rules": ["DESTRUCTIVE"], "target": "git reset --hard", "time": "2026-01-01T12:00:00+00:00", "tool": "Bash"}
```

The target (command or file path) is shortened to 200 characters.

## Example rules

`policy/agent_gate.rego` ships three example rules. Each has a code that shows
up in the log and in the reason.

| Code | Denies | Still allowed (examples) |
|---|---|---|
| `DESTRUCTIVE` | `git reset --hard`, `git clean -f`, `git push --force` (also `-f`, `--force-with-lease`, `+ref`), `rm -rf` on paths outside the working directory | `git reset --soft`, `git clean -n`, `rm -rf build` |
| `NETWORK` | `curl`, `wget`, `ssh` to hosts that are not local, `scp`/`sftp`/`rsync` to remote hosts, `curl "$URL"` without a recognizable target | `curl http://localhost:8080`, `ssh localhost` |
| `SERVICES` | `launchctl`, `systemctl`, `service`, `brew services` changes, `kill`, `pkill`, `killall` | `launchctl list`, `systemctl status x`, `kill %1` |

Settings live in `policy/data.json`:

```json
{
  "agent_gate_config": {
    "disabled": ["NETWORK"],
    "workdirs": ["/scratch"],
    "allowed_hosts": ["mirror.internal"]
  }
}
```

- `disabled`: rule codes that never fire.
- `workdirs`: extra directories in which `rm -rf` is allowed, besides the
  session's working directory.
- `allowed_hosts`: hosts that count as local for `NETWORK`.

## Writing your own rules

Add violations to the `raw_violations` set in package `agent_gate`, either in
`agent_gate.rego` or in a new file in the same package:

```rego
package agent_gate

raw_violations contains {"rule": "SECRETS", "reason": "writing .env files is not allowed"} if {
	input.tool in {"Write", "Edit"}
	endswith(input.file_path, ".env")
}
```

The helper `calls` gives you every command in a Bash line as
`{"name": "git", "args": ["push", "origin", "main"]}`, with prefixes like
`sudo` or `env X=1` removed. `input.role` lets you write rules per role, for
example a reviewer session that may not write at all.

Write tests next to the policy (`policy/*_test.rego`) and run `opa test policy -v`.
The project's own tests run with `python3 tests/test_gate.py`; cases that need
OPA print `SKIP opa missing` when no opa binary is found.

## Limits

Be honest about what this is:

- **experimental**: the rule set and the log format may change.
- **not a security boundary**: the command parser splits on shell separators
  and whitespace. It does not expand variables, aliases, scripts, nested
  shells (`bash -c`, `eval`) or other languages (`python -c`). A determined
  agent, or a prompt injection, can get around it.
- **not for production**: use it to make an agent's behaviour visible and to
  catch honest mistakes, next to real isolation (containers, separate users,
  no credentials in reach), not instead of it.
- A hook only sees the tools that pass through the hook. Anything the agent
  runs outside of Claude Code tool calls is invisible to the gate.

## Status and support

agent-gate is a personal side project, shared as a contribution, not as a
product. It is provided "as is", without warranty of any kind (see sections 7
and 8 of the license). Issues and pull requests are welcome and handled on a
best-effort basis; there is no support commitment.

This project is not affiliated with or endorsed by my employer. Claude Code is
a product of Anthropic; Open Policy Agent is a CNCF project. Both are used here
as documented, unmodified tools.

## License

Copyright 2026 Dominik Dietrich. Licensed under the Apache License, Version 2.0;
see [LICENSE](LICENSE) and [NOTICE](NOTICE).
