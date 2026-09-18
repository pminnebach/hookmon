# hookmon

Relay coding-agent hook payloads to a local console listener. One binary, two roles:

- `hookmon listen` — long-running TCP server; prints each envelope
- `hookmon send` — invoked by the agent as a command hook; forwards stdin JSON

Cursor and Claude Code are supported agent providers. Others plug in via `agent.Provider`.

## Build

```bash
go build -o hookmon .
```

## Run

```bash
# terminal 1
./hookmon listen
# or: ./hookmon listen --log-file ./hooks.log

# terminal 2 / Cursor hooks.json
./hookmon send --agent cursor   # reads hook JSON from stdin
```

Default address: `127.0.0.1:9473` (`--addr`, `HOOKMON_ADDR`, or `.hookmon.yaml`).
`--log-file` (or `HOOKMON_LOG_FILE`) redirects listen output to a file (absolute or relative path).

## Cursor hooks

Copy [examples/cursor/hooks.json](examples/cursor/hooks.json) to `~/.cursor/hooks.json` or project `.cursor/hooks.json`. Point `command` at your binary:

```json
"command": "/absolute/path/to/hookmon send --agent cursor"
```

Wire format:

```json
{ "agent": "cursor", "payload": { /* raw hook JSON */ } }
```

`send` always acknowledges with `{}` and fails open if the listener is down.

## Claude Code hooks

Claude Code hooks come in two flavors: `type: "http"` (Claude Code POSTs the
hook JSON straight to a URL) and `type: "command"` (a local script gets the
hook JSON on stdin). hookmon uses **command hooks** — `hookmon send --agent
claudecode` *is* the script; it forwards to the same TCP listener every other
agent uses, so there's no separate HTTP server or auth story to build.

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
          { "type": "command", "command": "${CLAUDE_PROJECT_DIR}/hookmon send --agent claudecode" }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "${CLAUDE_PROJECT_DIR}/hookmon send --agent claudecode" }
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
2. `./hookmon listen` in one terminal.
3. Open this project in Claude Code and run `/hooks` — you should see
   `claudecode` handlers registered for every event.
4. Trigger any tool call (e.g. ask Claude to run `ls`); `hookmon listen`
   should print an envelope tagged `"agent": "claudecode"`.

You can also test the relay directly without Claude Code:

```bash
echo '{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"cwd":"/workspace","transcript_path":"/tmp/t.json"}' | ./hookmon send --agent claudecode
echo '{"session_id":"test","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_response":"hi","cwd":"/workspace","transcript_path":"/tmp/t.json"}' | ./hookmon send --agent claudecode
```

Both should show up in `hookmon listen`'s output tagged `"agent": "claudecode"`.

## Adding an agent

1. Implement `agent.Provider` in `agent/<name>/`
2. `agent.Register` in `init()`
3. Blank-import the package from `cmd`
4. Add `examples/<name>/` hook config
