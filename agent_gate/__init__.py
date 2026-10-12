"""agent-gate: an OPA policy gate for coding agents, run as a PreToolUse hook.

The hook reads the PreToolUse document from stdin, asks OPA for a verdict and
answers with an exit code: 0 lets the tool call run, 2 makes the agent refuse it.
"""

__version__ = "0.1.0"
