# agent-gate example policy.
#
# Input (built by agent_gate from the PreToolUse document):
#   {"tool": "Bash", "command": "...", "file_path": "...", "cwd": "...", "role": "..."}
#
# Output: data.agent_gate.decision = {"allow": bool, "violations": [{"rule", "reason"}]}
#
# Three example rules, each with a code:
#   DESTRUCTIVE  git reset --hard, git clean -f, git push --force,
#                rm -rf on paths outside the working directory
#   NETWORK      curl, wget, ssh, scp, rsync to hosts that are not local
#   SERVICES     launchctl, systemctl, service, brew services, kill, pkill, killall
#
# Settings live in data.json under "agent_gate_config":
#   disabled       rule codes that never fire, e.g. ["NETWORK"]
#   workdirs       extra directories in which rm -rf is allowed (besides cwd)
#   allowed_hosts  hosts that count as local for NETWORK
#
# The command parser is deliberately simple: it splits on shell separators and
# whitespace. It does not expand variables, aliases or nested shells.
package agent_gate

decision := {
	"allow": count(violations) == 0,
	"violations": [v | some v in violations],
}

rules := {v.rule | some v in violations}

violations contains v if {
	some v in raw_violations
	not v.rule in config_list("disabled")
}

config_list(key) := value if {
	value := data.agent_gate_config[key]
} else := []

# --- command parsing ---------------------------------------------------------

separators := `\s*(?:&&|\|\||;|\||&|\n|\$\(|\(|\)|\x60)\s*`

segments contains words if {
	input.tool == "Bash"
	some part in regex.split(separators, input.command)
	words := [trim(w, `"'`) | some w in regex.split(`\s+`, trim_space(part)); w != ""]
	count(words) > 0
}

prefix_words := {"sudo", "doas", "env", "exec", "nohup", "time", "command", "nice", "xargs"}

is_prefix(w) if w in prefix_words

is_prefix(w) if regex.match(`^[A-Za-z_][A-Za-z0-9_]*=`, w)

command_at(words) := [i, name] if {
	some i, w in words
	not is_prefix(w)
	count([k | some k, x in words; k < i; not is_prefix(x)]) == 0
	name := regex.replace(w, `^.*/`, "")
}

calls contains {"name": name, "args": args} if {
	some words in segments
	[i, name] := command_at(words)
	args := array.slice(words, i + 1, count(words))
}

operands(args) := [a | some a in args; not startswith(a, "-")]

first_operand(args) := operands(args)[0] if {
	count(operands(args)) > 0
} else := ""

previous_in(args, i, flags) if {
	i > 0
	args[i - 1] in flags
}

# --- DESTRUCTIVE -------------------------------------------------------------

raw_violations contains {"rule": "DESTRUCTIVE", "reason": "git reset --hard discards uncommitted work"} if {
	some c in calls
	c.name == "git"
	"reset" in c.args
	"--hard" in c.args
}

raw_violations contains {"rule": "DESTRUCTIVE", "reason": "git clean -f deletes untracked files"} if {
	some c in calls
	c.name == "git"
	"clean" in c.args
	some a in c.args
	force_flag(a)
}

raw_violations contains {"rule": "DESTRUCTIVE", "reason": "git push --force rewrites remote history"} if {
	some c in calls
	c.name == "git"
	"push" in c.args
	some a in c.args
	push_force(a)
}

raw_violations contains {"rule": "DESTRUCTIVE", "reason": sprintf("rm -rf outside the working directory: %s", [t])} if {
	some c in calls
	c.name == "rm"
	rm_recursive(c.args)
	rm_force(c.args)
	some t in operands(c.args)
	outside_workdir(t)
}

force_flag(a) if a == "--force"

force_flag(a) if regex.match(`^-[A-Za-z]*f[A-Za-z]*$`, a)

push_force(a) if force_flag(a)

push_force(a) if startswith(a, "--force")

push_force(a) if regex.match(`^\+[^+]`, a)

short_flags(args) := concat("", [substring(a, 1, -1) | some a in args; regex.match(`^-[A-Za-z]+$`, a)])

rm_recursive(args) if contains(short_flags(args), "r")

rm_recursive(args) if contains(short_flags(args), "R")

rm_recursive(args) if "--recursive" in args

rm_force(args) if contains(short_flags(args), "f")

rm_force(args) if "--force" in args

allowed_dirs contains d if {
	d := trim_right(input.cwd, "/")
	d != ""
}

allowed_dirs contains d if {
	some x in config_list("workdirs")
	d := trim_right(x, "/")
	d != ""
}

# Only paths strictly below an allowed directory are inside.
inside_workdir(t) if {
	some d in allowed_dirs
	startswith(t, concat("", [d, "/"]))
	trim_right(t, "/") != d
}

outside_workdir(t) if startswith(t, "~")

outside_workdir(t) if startswith(t, "$")

outside_workdir(t) if regex.match(`(^|/)\.\.(/|$)`, t)

outside_workdir(t) if {
	startswith(t, "/")
	not inside_workdir(t)
}

# --- NETWORK -----------------------------------------------------------------

http_clients := {"curl", "wget"}

remote_shells := {"ssh"}

remote_copies := {"scp", "sftp", "rsync"}

http_value_flags := {
	"-o", "-d", "-H", "-X", "-u", "-A", "-e", "-T", "-F", "-K", "-b", "-c", "-m", "-w",
	"-O", "-P", "-a", "-U",
	"--output", "--data", "--header", "--request", "--user", "--user-agent",
	"--referer", "--upload-file", "--form", "--config", "--cookie", "--cookie-jar",
	"--max-time", "--connect-timeout", "--retry", "--write-out",
	"--output-document", "--directory-prefix",
}

ssh_value_flags := {
	"-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m",
	"-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
}

copy_value_flags := {"-i", "-P", "-F", "-o", "-l", "-c", "-S", "-J", "-e"}

local_hosts := {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}

is_local(h) if h in local_hosts

is_local(h) if regex.match(`^127\.`, h)

is_local(h) if endswith(h, ".localhost")

is_local(h) if h in config_list("allowed_hosts")

url_host(a) := lower(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`^[A-Za-z][A-Za-z0-9+.-]*://(?:[^/@]*@)?(\[[^\]]*\]|[^/:?#]+)`, a, 1)
	count(m) == 1
}

remote_host(a) := lower(m[0][1]) if {
	m := regex.find_all_string_submatch_n(`^(?:[A-Za-z]+://)?(?:[^@/]*@)?(\[[^\]]*\]|[^:/]+)`, a, 1)
	count(m) == 1
}

bare_host(a) if regex.match(`^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:[0-9]+)?(/.*)?$`, a)

bare_host(a) if regex.match(`^localhost(:[0-9]+)?(/.*)?$`, a)

http_hosts(args) := {h | some a in args; h := url_host(a)} | {h |
	some i, a in args
	not contains(a, "://")
	not startswith(a, "-")
	not previous_in(args, i, http_value_flags)
	bare_host(a)
	h := remote_host(a)
}

ssh_operand(args, i) if {
	not startswith(args[i], "-")
	not previous_in(args, i, ssh_value_flags)
}

# The destination is the first operand; later operands are the remote command.
ssh_hosts(args) := {h |
	some i, a in args
	ssh_operand(args, i)
	count([j | some j, _ in args; j < i; ssh_operand(args, j)]) == 0
	h := remote_host(a)
}

copy_hosts(args) := {h |
	some i, a in args
	not startswith(a, "-")
	not previous_in(args, i, copy_value_flags)
	regex.match(`^[^/]*:`, a)
	h := remote_host(a)
}

network_targets(c) := http_hosts(c.args) if c.name in http_clients

network_targets(c) := ssh_hosts(c.args) if c.name in remote_shells

network_targets(c) := copy_hosts(c.args) if c.name in remote_copies

raw_violations contains {"rule": "NETWORK", "reason": sprintf("%s to external host %s", [c.name, h])} if {
	some c in calls
	some h in network_targets(c)
	not is_local(h)
}

# A client without a recognizable target (for example curl "$URL") is not trusted.
raw_violations contains {"rule": "NETWORK", "reason": sprintf("%s without a recognizable local target", [c.name])} if {
	some c in calls
	c.name in (http_clients | remote_shells)
	count(network_targets(c)) == 0
}

# --- SERVICES ----------------------------------------------------------------

launchctl_read_only := {"list", "print", "print-disabled", "help", "version", "blame", "error"}

systemctl_read_only := {
	"status", "show", "cat", "help", "is-active", "is-enabled", "is-failed",
	"list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies",
}

service_changes := {"start", "stop", "restart", "reload", "force-reload", "kill", "run", "enable", "disable"}

raw_violations contains {"rule": "SERVICES", "reason": sprintf("launchctl %s changes system services", [sub])} if {
	some c in calls
	c.name == "launchctl"
	sub := first_operand(c.args)
	not sub in launchctl_read_only
}

raw_violations contains {"rule": "SERVICES", "reason": sprintf("systemctl %s changes system services", [sub])} if {
	some c in calls
	c.name == "systemctl"
	sub := operands(c.args)[0]
	not sub in systemctl_read_only
}

raw_violations contains {"rule": "SERVICES", "reason": sprintf("service %s changes system services", [concat(" ", c.args)])} if {
	some c in calls
	c.name == "service"
	some a in c.args
	a in service_changes
}

raw_violations contains {"rule": "SERVICES", "reason": sprintf("brew services %s changes system services", [c.args[1]])} if {
	some c in calls
	c.name == "brew"
	c.args[0] == "services"
	c.args[1] in service_changes
}

raw_violations contains {"rule": "SERVICES", "reason": sprintf("%s stops processes", [c.name])} if {
	some c in calls
	c.name in {"pkill", "killall"}
}

# kill is allowed for shell jobs (%1) and for listing signals (-l).
raw_violations contains {"rule": "SERVICES", "reason": "kill stops processes"} if {
	some c in calls
	c.name == "kill"
	not kill_harmless(c.args)
}

kill_harmless(args) if "-l" in args

kill_harmless(args) if "-L" in args

kill_harmless(args) if {
	count(operands(args)) > 0
	every a in operands(args) {
		startswith(a, "%")
	}
}
