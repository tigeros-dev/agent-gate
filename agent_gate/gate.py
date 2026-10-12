"""The gate: PreToolUse document in, OPA verdict out, one log line per verdict.

Configuration comes from the environment:

    AGENT_GATE_MODE        observe (default) or enforce
    AGENT_GATE_ROLE        role of the agent session (default "default")
    AGENT_GATE_OPA         path to the opa binary (default: opa in PATH)
    AGENT_GATE_POLICY_DIR  directory with the policies (default ./policy)
    AGENT_GATE_LOG         JSON lines log file (default ./agent-gate.log.jsonl)

Exit codes follow the Claude Code hook contract: 0 lets the tool call run,
2 blocks it and hands stderr to the agent as the reason.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

MODES = ("observe", "enforce")
DEFAULT_MODE = "observe"
DEFAULT_ROLE = "default"
DEFAULT_POLICY_DIR = "policy"
DEFAULT_LOG = "agent-gate.log.jsonl"
QUERY = "data.agent_gate.decision"
OPA_TIMEOUT_SECONDS = 10
TARGET_LIMIT = 200
GATE_ERROR = "GATE_ERROR"
RC_ALLOW = 0
RC_BLOCK = 2


class GateError(Exception):
    """The gate itself could not reach a verdict."""


def settings(environ=None):
    """Read the gate configuration from the environment."""
    env = os.environ if environ is None else environ
    return {
        "mode": (env.get("AGENT_GATE_MODE") or DEFAULT_MODE).strip().lower(),
        "role": env.get("AGENT_GATE_ROLE") or DEFAULT_ROLE,
        "opa": env.get("AGENT_GATE_OPA") or "",
        "policy_dir": env.get("AGENT_GATE_POLICY_DIR") or DEFAULT_POLICY_DIR,
        "log": env.get("AGENT_GATE_LOG") or DEFAULT_LOG,
    }


def build_input(raw, role):
    """Turn the PreToolUse JSON text into the input document for OPA."""
    try:
        event = json.loads(raw)
    except ValueError as error:
        raise GateError("stdin is not valid JSON: %s" % error) from None
    if not isinstance(event, dict):
        raise GateError("stdin is not a JSON object")
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise GateError("PreToolUse document has no tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    command = tool_input.get("command")
    file_path = (tool_input.get("file_path") or tool_input.get("notebook_path")
                 or tool_input.get("path"))
    cwd = event.get("cwd")
    return {
        "tool": tool,
        "command": command if isinstance(command, str) else "",
        "file_path": file_path if isinstance(file_path, str) else "",
        "cwd": cwd if isinstance(cwd, str) else os.getcwd(),
        "role": role,
    }


def find_opa(configured):
    """Path to the opa binary; a configured path is never replaced by PATH."""
    if configured:
        if Path(configured).is_file() and os.access(configured, os.X_OK):
            return configured
        raise GateError("opa binary not found at AGENT_GATE_OPA=%s" % configured)
    found = shutil.which("opa")
    if not found:
        raise GateError("opa binary not found in PATH (set AGENT_GATE_OPA)")
    return found


def ask_opa(opa, policy_dir, document):
    """Evaluate the decision rule; returns (allowed, [violation, ...])."""
    if not Path(policy_dir).is_dir():
        raise GateError("policy directory not found: %s" % policy_dir)
    command = [opa, "eval", "--format", "json", "--stdin-input",
               "--data", str(policy_dir), QUERY]
    try:
        done = subprocess.run(command, input=json.dumps(document), capture_output=True,
                              text=True, timeout=OPA_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        raise GateError("opa eval timed out after %ss" % OPA_TIMEOUT_SECONDS) from None
    except OSError as error:
        raise GateError("opa could not be started: %s" % error) from None
    if done.returncode != 0:
        raise GateError("opa eval failed: %s" % first_line(done.stderr or done.stdout))
    try:
        value = json.loads(done.stdout)["result"][0]["expressions"][0]["value"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise GateError("policy returned no decision for %s" % QUERY) from None
    if not isinstance(value, dict) or not isinstance(value.get("allow"), bool):
        raise GateError("decision is not an object with a boolean 'allow'")
    violations = value.get("violations") or []
    if not isinstance(violations, list):
        raise GateError("decision 'violations' is not a list")
    return value["allow"] and not violations, violations


def first_line(text):
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return shorten(lines[0] if lines else "no output", TARGET_LIMIT)


def shorten(text, limit=TARGET_LIMIT):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def rule_codes(violations):
    codes = []
    for item in violations:
        code = item.get("rule") if isinstance(item, dict) else item
        if code and str(code) not in codes:
            codes.append(str(code))
    return codes


def reasons(violations):
    out = []
    for item in violations:
        if isinstance(item, dict):
            out.append("%s: %s" % (item.get("rule", "?"), item.get("reason", "")))
        else:
            out.append(str(item))
    return out


def write_log(path, entry):
    """Append one JSON line; a log failure is reported, never fatal."""
    try:
        log = Path(path)
        if log.parent and not log.parent.exists():
            log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    except OSError as error:
        print("agent-gate: cannot write log %s: %s" % (path, error), file=sys.stderr)


def log_entry(conf, mode, document, decision, rules, **extra):
    target = ""
    tool = ""
    if document:
        tool = document.get("tool", "")
        target = document.get("command") or document.get("file_path") or ""
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": tool,
        "target": shorten(target),
        "role": conf["role"],
        "mode": mode,
        "decision": decision,
        "rules": rules,
    }
    entry.update(extra)
    return entry


def main(stdin=None, environ=None):
    """Run the gate once; returns the exit code for the hook."""
    conf = settings(environ)
    stream = sys.stdin if stdin is None else stdin
    mode = conf["mode"]
    document = None
    try:
        if mode not in MODES:
            mode = "enforce"
            raise GateError("unknown AGENT_GATE_MODE %r (use observe or enforce)"
                            % conf["mode"])
        document = build_input(stream.read(), conf["role"])
        opa = find_opa(conf["opa"])
        allowed, violations = ask_opa(opa, conf["policy_dir"], document)
    except GateError as error:
        return gate_failed(conf, mode, document, str(error))

    codes = rule_codes(violations)
    decision = "allow" if allowed else "deny"
    write_log(conf["log"], log_entry(conf, mode, document, decision, codes,
                                     reasons=reasons(violations)))
    if allowed or mode == "observe":
        return RC_ALLOW
    print("agent-gate: denied by policy: " + "; ".join(reasons(violations)),
          file=sys.stderr)
    return RC_BLOCK


def gate_failed(conf, mode, document, message):
    """observe fails open, enforce fails closed; both write a log line."""
    decision = "allow" if mode == "observe" else "deny"
    write_log(conf["log"], log_entry(conf, mode, document, decision, [GATE_ERROR],
                                     error=shorten(message)))
    if mode == "observe":
        return RC_ALLOW
    print("agent-gate: gate error, call blocked (fail-closed): " + message,
          file=sys.stderr)
    return RC_BLOCK
