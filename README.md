# hookmon

Log coding-agent hook payloads to a file. One binary, invoked directly by the
agent's hook system as each event fires — no server to start, no port to
coordinate.

Cursor and Claude Code are supported agent providers. Others plug in via `agent.Provider`.

## Build

```bash
go build -o hookmon .
```

## Run

Point your agent's hook config at the binary (see below), and pass
`--log-file` so events get persisted:

```bash
./hookmon --agent cursor --log-file ./hooks.log
```

Every invocation reads the hook JSON from stdin, appends it (wrapped in an
envelope naming the agent) to `--log-file`, and acknowledges. If `--log-file`
is unset, hookmon still acknowledges but doesn't record anything — set it to
capture events.

Default log file: none (`--log-file`, `HOOKMON_LOG_FILE`, or `.hookmon.yaml`).

## Blocking tool calls with policy

By default hookmon only observes — every hook call is acknowledged as
allowed. To actually **block** specific tools at specific hook events, add a
shared, checked-in policy file (see
[examples/policy/.hookmon-policy.yaml](examples/policy/.hookmon-policy.yaml)):

```yaml
rules:
  - event: PreToolUse
    agent: claudecode
    tools: ["Bash"]
    action: deny
    reason: "Direct Bash calls are blocked by hookmon policy."

default-action: allow
```

Point hookmon at it with `--policy-file`, `HOOKMON_POLICY_FILE`, or
`policy-file:` in `.hookmon.yaml` (default: `.hookmon-policy.yaml` in the
current directory). Each rule matches a hook `event` name (agent-native
casing, e.g. `PreToolUse` for Claude Code, `preToolUse` for Cursor),
optionally scoped to one `agent`, one or more exact `tools`, and/or one or
more `paths`; `action` is `allow`, `deny`, or `ask`. When several rules
match, the strictest wins (`deny` > `ask` > `allow`).

`tools` and `paths` both AND with the rest of the rule (and with each other)
— a rule needs every filter it specifies to match. `paths` scopes a rule to
specific files, e.g. to block reads/writes of `.env` without blocking `Read`/
`Write` outright:

```yaml
- event: PreToolUse
  agent: claudecode
  tools: ["Read", "Write"]
  paths: [".env"]
  action: deny
  reason: ".env files are blocked by hookmon policy."
```

Path patterns are matched gitignore-style against `tool_input.file_path`
(currently populated for Claude Code only): a bare pattern like `.env` or
`*.env` matches the filename at any depth by comparing whole path
components, never a substring — so `foo.envelope.txt` is correctly **not**
caught by `.env`. A pattern ending in `/` (e.g. `.git/`) anchors to a
directory component instead of the filename. A rule with `paths` set but no
matching file path in the event (e.g. a `Bash` call, which has no
`file_path`) simply doesn't match — same fail-open rule as everything else.

**Fail-open by design**, matching every other error path in hookmon: a
missing policy file, a policy file that fails to parse, or a hook/tool that
matches no rule all behave exactly like no policy being configured at all —
they never block anything. Logging is unaffected either way: a denied call
still gets written to `--log-file`.

Only a subset of hook events actually support blocking, because each
event's real acknowledgment schema differs:

- **Claude Code**: only `PreToolUse` (via
  `hookSpecificOutput.permissionDecision`). Other events use a different,
  unimplemented `decision` schema and are always acknowledged with `{}`
  regardless of matching rules.
- **Cursor**: `preToolUse`, `postToolUse`, `postToolUseFailure`,
  `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`,
  `subagentStart`, `beforeTabFileRead` (via `{"permission": ...}`).

## Cursor hooks

Copy [examples/cursor/hooks.json](examples/cursor/hooks.json) to `~/.cursor/hooks.json` or project `.cursor/hooks.json`. Point `command` at your binary:

```json
"command": "/absolute/path/to/hookmon --agent cursor --log-file /absolute/path/to/hooks.log"
```

Wire format:

```json
{ "agent": "cursor", "payload": { /* raw hook JSON */ } }
```

hookmon always acknowledges with `{}` and fails open (writes a warning to
stderr but still acknowledges) if logging fails.

## Claude Code hooks

Claude Code hooks come in two flavors: `type: "http"` (Claude Code POSTs the
hook JSON straight to a URL) and `type: "command"` (a local script gets the
hook JSON on stdin). hookmon uses **command hooks** — `hookmon --agent
claudecode` *is* the script; it appends straight to a log file, so there's no
separate HTTP server or auth story to build.

Copy [examples/claudecode/settings.json](examples/claudecode/settings.json)
into `.claude/settings.json` (shared with your team, check it in) or
`.claude/settings.local.json` (personal-only, usually gitignored) in your
project. It registers every documented Claude Code hook event, matching
tool-related ones with `"matcher": "*"`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "${CLAUDE_PROJECT_DIR}/hookmon --agent claudecode --log-file ${CLAUDE_PROJECT_DIR}/hooks.log" }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "${CLAUDE_PROJECT_DIR}/hookmon --agent claudecode --log-file ${CLAUDE_PROJECT_DIR}/hooks.log" }
        ]
      }
    ]
  }
}
```

`${CLAUDE_PROJECT_DIR}` is set by Claude Code to the project root, so the
config works regardless of where the repo is checked out. No env vars or
secrets are needed — hookmon has no auth.

This repo dogfoods its own Claude Code integration via the committed
[.claude/settings.json](.claude/settings.json), the same way
[.agents/hooks.json](.agents/hooks.json) dogfoods Cursor.

**Verify it's working:**

1. `go build -o hookmon .`
2. Open this project in Claude Code and run `/hooks` — you should see
   `claudecode` handlers registered for every event.
3. Trigger any tool call (e.g. ask Claude to run `ls`); the configured
   `--log-file` should gain an envelope tagged `"agent": "claudecode"`.

You can also test hookmon directly without Claude Code:

```bash
echo '{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"cwd":"/workspace","transcript_path":"/tmp/t.json"}' | ./hookmon --agent claudecode --log-file ./hooks.log
echo '{"session_id":"test","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_response":"hi","cwd":"/workspace","transcript_path":"/tmp/t.json"}' | ./hookmon --agent claudecode --log-file ./hooks.log
cat ./hooks.log
```

Both should show up in `hooks.log` tagged `"agent": "claudecode"`.

## Adding an agent

1. Implement `agent.Provider` in `agent/<name>/`
2. `agent.Register` in `init()`
3. Blank-import the package from `cmd`
4. Add `examples/<name>/` hook config
