"""Tests for agent-gate: runs python -m agent_gate as a subprocess.

Usage: python3 tests/test_gate.py

The gate is fed real Claude Code PreToolUse documents. Cases that need OPA use
AGENT_GATE_OPA or opa in PATH; without either they print "SKIP opa missing"
instead of passing silently. Exit code 0 when no case failed; the last line is
"STATUS: PASS" or "STATUS: FAIL", with the number of skipped cases if any.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
POLICY = PROJECT / "policy"
GATE_ENV = ("AGENT_GATE_ROLE", "AGENT_GATE_OPA", "AGENT_GATE_POLICY_DIR",
            "AGENT_GATE_MODE", "AGENT_GATE_LOG")


def pre_tool_use(tool, tool_input, cwd="/tmp/project"):
    return json.dumps({
        "session_id": "test-session",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
    })


def bash(command):
    return pre_tool_use("Bash", {"command": command, "description": "test"})


def find_opa():
    configured = os.environ.get("AGENT_GATE_OPA")
    if configured and Path(configured).is_file():
        return configured
    return shutil.which("opa")


class Runner:
    def __init__(self, work, opa):
        self.work = Path(work)
        self.opa = opa
        self.count = 0
        self.failed = 0
        self.skipped = 0

    def gate(self, stdin_text, mode, opa=None, policy=POLICY, role=None):
        """Run the gate once; returns (rc, stderr, log entries)."""
        self.count += 1
        log = self.work / ("gate%d.jsonl" % self.count)
        env = {k: v for k, v in os.environ.items() if k not in GATE_ENV}
        env.update({
            "AGENT_GATE_MODE": mode,
            "AGENT_GATE_LOG": str(log),
            "AGENT_GATE_POLICY_DIR": str(policy),
            "AGENT_GATE_OPA": str(opa if opa is not None else (self.opa or "")),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        if role is not None:
            env["AGENT_GATE_ROLE"] = role
        done = subprocess.run([sys.executable, "-m", "agent_gate"], input=stdin_text,
                              cwd=str(PROJECT), env=env, capture_output=True,
                              text=True, timeout=60, check=False)
        entries = []
        if log.exists():
            entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()
                       if line.strip()]
        return done.returncode, done.stderr, entries

    def check(self, name, ok, detail=""):
        print("%-4s %s" % ("ok" if ok else "FAIL", name))
        if not ok:
            self.failed += 1
            print("     " + str(detail)[:300])

    def needs_opa(self, name):
        if self.opa:
            return True
        self.skipped += 1
        print("SKIP opa missing: " + name)
        return False


def cases_without_opa(run):
    missing = run.work / "nowhere" / "opa"

    rc, _err, log = run.gate("{not json", "observe")
    run.check("invalid JSON in observe fails open with a log line",
              rc == 0 and len(log) == 1 and log[0]["rules"] == ["GATE_ERROR"], (rc, log))

    rc, err, log = run.gate("{not json", "enforce")
    run.check("invalid JSON in enforce fails closed", rc == 2 and "not valid JSON" in err,
              (rc, err))

    rc, _err, log = run.gate(bash("ls"), "observe", opa=missing)
    run.check("missing opa in observe fails open", rc == 0 and len(log) == 1, (rc, log))

    rc, err, log = run.gate(bash("ls"), "enforce", opa=missing)
    run.check("missing opa in enforce fails closed",
              rc == 2 and "opa" in err and log and log[0]["decision"] == "deny", (rc, err, log))

    rc, err, _log = run.gate(bash("ls"), "loud")
    run.check("unknown mode fails closed", rc == 2 and "AGENT_GATE_MODE" in err, (rc, err))


def cases_with_opa(run):
    verdicts = [
        ("ls is allowed", bash("ls -la"), "allow", None),
        ("git reset --hard is DESTRUCTIVE", bash("git reset --hard"), "deny", "DESTRUCTIVE"),
        ("git push --force is DESTRUCTIVE", bash("git push -f origin main"), "deny", "DESTRUCTIVE"),
        ("rm -rf outside cwd is DESTRUCTIVE", bash("rm -rf /var/lib/app"), "deny", "DESTRUCTIVE"),
        ("rm -rf inside cwd is allowed", bash("rm -rf node_modules"), "allow", None),
        ("curl to an external host is NETWORK", bash("curl https://example.com"), "deny", "NETWORK"),
        ("curl to localhost is allowed", bash("curl localhost:3000/health"), "allow", None),
        ("systemctl restart is SERVICES", bash("systemctl restart nginx"), "deny", "SERVICES"),
        ("systemctl status is allowed", bash("systemctl status nginx"), "allow", None),
        ("Write is allowed", pre_tool_use("Write", {"file_path": "/tmp/project/a.md",
                                                    "content": "x"}), "allow", None),
    ]
    for name, stdin_text, expected, code in verdicts:
        if not run.needs_opa(name):
            continue
        rc, err, log = run.gate(stdin_text, "enforce")
        entry = log[0] if log else {}
        ok = len(log) == 1 and entry.get("decision") == expected
        if expected == "deny":
            ok = ok and rc == 2 and code in err and code in entry.get("rules", [])
        else:
            ok = ok and rc == 0 and entry.get("rules") == []
        run.check(name, ok, (rc, err, log))

    name = "observe logs a deny but returns 0"
    if run.needs_opa(name):
        rc, err, log = run.gate(bash("git clean -fd"), "observe", role="reviewer")
        entry = log[0] if log else {}
        run.check(name, rc == 0 and err == "" and entry.get("decision") == "deny"
                  and entry.get("role") == "reviewer" and entry.get("mode") == "observe",
                  (rc, err, log))

    name = "disabled rule does not fire"
    if run.needs_opa(name):
        policy = run.work / "policy_disabled"
        shutil.copytree(POLICY, policy)
        data_file = policy / "data.json"
        data = json.loads(data_file.read_text(encoding="utf-8"))
        data["agent_gate_config"]["disabled"] = ["SERVICES"]
        data_file.write_text(json.dumps(data), encoding="utf-8")
        rc, _err, log = run.gate(bash("pkill -f worker"), "enforce", policy=policy)
        run.check(name, rc == 0 and log and log[0]["decision"] == "allow", (rc, log))

    name = "broken policy in enforce fails closed"
    if run.needs_opa(name):
        broken = run.work / "policy_broken"
        broken.mkdir()
        (broken / "agent_gate.rego").write_text("package agent_gate\nnot rego {\n",
                                                encoding="utf-8")
        rc, err, _log = run.gate(bash("ls"), "enforce", policy=broken)
        run.check(name, rc == 2 and "opa eval failed" in err, (rc, err))


def main():
    opa = find_opa()
    with tempfile.TemporaryDirectory() as work:
        run = Runner(work, opa)
        cases_without_opa(run)
        cases_with_opa(run)
    print("%d failed, %d skipped" % (run.failed, run.skipped))
    status = "FAIL" if run.failed else "PASS"
    if run.skipped:
        status += " (%d skipped: opa missing)" % run.skipped
    print("STATUS: " + status)
    return 1 if run.failed else 0


if __name__ == "__main__":
    sys.exit(main())
