# Security policy

agent-gate is experimental. It is not a security boundary and not meant for
production use; see the limits section in the README.

## Reporting a problem

If you find a way to bypass a rule, a crash that makes the gate fail open in
enforce mode, or any other security relevant issue, please write to
**hello@tigeros.dev** instead of opening a public issue.

Please include:

- the agent-gate version (`agent_gate.__version__`) and the OPA version,
- the PreToolUse document or command that shows the problem,
- what you expected and what happened.

This is a small project maintained in spare time; reports are answered as soon
as possible, and reporters are credited unless they ask not to be.

## Supported versions

Only the latest release receives fixes.
