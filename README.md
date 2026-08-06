# hookmon

Relay coding-agent hook payloads to a local console listener. One binary, two roles:

- `hookmon listen` — long-running TCP server; prints each envelope
- `hookmon send` — invoked by the agent as a command hook; forwards stdin JSON

Cursor is the first agent provider. Others plug in via `agent.Provider`.

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

## Adding an agent

1. Implement `agent.Provider` in `agent/<name>/`
2. `agent.Register` in `init()`
3. Blank-import the package from `cmd`
4. Add `examples/<name>/` hook config
