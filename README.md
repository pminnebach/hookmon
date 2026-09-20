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
optionally scoped to one `agent`, one or more exact `tools`, one or more
`paths`, and/or one or more `commands`; `action` is `allow`, `deny`, or
`ask`. When several rules match, the strictest wins (`deny` > `ask` >
`allow`).

`tools`, `paths`, and `commands` all AND with the rest of the rule (and with
each other) — a rule needs every filter it specifies to match. `paths`
scopes a rule to specific files, e.g. to block reads/writes of `.env`
without blocking `Read`/`Write` outright:

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

`commands` scopes a rule to Bash calls whose command string contains one of
the given substrings (matched against `tool_input.command`, Claude Code
only), e.g. to block `git push` without blocking `Bash` outright:

```yaml
- event: PreToolUse
  agent: claudecode
  tools: ["Bash"]
  commands: ["git push"]
  action: deny
  reason: "git push is blocked by hookmon policy."
```

Matching is a plain substring test, not a glob or regex, so `"git push"`
also catches `"git push --force"` and `"git push origin main"`. A rule with
`commands` set but no command in the event (e.g. a non-Bash tool) simply
doesn't match — same fail-open rule as `paths`.

Other commands worth considering for a `commands` rule in an agentic coding
setup: `rm -rf` (destructive deletes), `git reset --hard` / `git clean -fd`
(silently discards uncommitted work), `sudo` (privilege escalation), and
`curl`/`wget` (especially piped into a shell — a remote-code-execution
pattern). A rule's `commands` list can hold several patterns at once (any
one matching is enough), and `action: ask` is worth using instead of `deny`
for a lower-confidence match like bare `curl`/`wget`, where the command
itself isn't inherently dangerous:

```yaml
- event: PreToolUse
  agent: claudecode
  tools: ["Bash"]
  commands: ["rm -rf", "git reset --hard", "sudo"]
  action: deny
  reason: "This command is blocked by hookmon policy."

- event: PreToolUse
  agent: claudecode
  tools: ["Bash"]
  commands: ["curl", "wget"]
  action: ask
  reason: "Network downloads via Bash require confirmation."
```

As with `git push`, substring matching is blunt here — `"rm -rf"` also
catches harmless cleanup like `"rm -rf ./build"`, and `"sudo"` also catches
read-only uses like `"sudo apt list"`. See
[examples/policy/.hookmon-policy.yaml](examples/policy/.hookmon-policy.yaml)
for the full versions of these rules.

## Semantic rules with `when:`

Substring and glob matching can only enumerate spellings, never state a
condition. `commands: ["rm -rf"]` blocks harmless `rm -rf ./build` and misses
`rm -r -f ./src`, `/bin/rm -rf src`, and anything through `eval`. A `when:`
clause asks what the call would actually *do*:

```yaml
judgments:
  destroys_work:
    type: noul
    instructions: >
      Would running this irreversibly destroy source code, uncommitted
      changes, or data the user could not easily recover?
    criteria:
      "true": "It loses work with no straightforward undo."
      "false": "It only affects regenerable artifacts — build output, caches, dependencies."

rules:
  - event: PreToolUse
    tools: ["Bash"]
    when: { destroys_work: ">= 0.85" }
    on-error: ask
    action: deny
    reason: "This command would irreversibly destroy work."
```

Judgments are answered by [TypeSafe](https://typesafe.ai)'s System One model,
which returns a typed probability rather than generated text. Code keeps
everything deterministic — event, agent and tool matching, rule precedence,
thresholds, and the fail-open contract; the model supplies only the semantic
judgment about the unstructured command or path.

### Declaring judgments

Each entry under `judgments:` has a `type`, `instructions`, and optional
`criteria`:

| Type | Answers with | `criteria` shape |
| --- | --- | --- |
| `noul` | a probability from 0 to 1 | optional map: `{"true": …, "false": …}` |
| `choice` | one of your options | map of option name to description |
| `score` | a position along ordered levels | ordered list, one description per level |

Write one narrow judgment per question, and make each criterion describe a
concrete situation that stands on its own.

### Thresholds

`when:` maps a judgment to a condition. Every entry must hold (AND):

```yaml
when:
  destroys_work: ">= 0.85"     # noul probability
  blast_radius: ">= 2"         # score level
  destination: "== shared"     # choice option
  destination.confidence: ">= 0.6"
```

Operators are `>=`, `>`, `<=`, `<`, `==`, `!=`. A bare number means `>=` and a
bare word means `==`, so `destroys_work: 0.85` works unquoted. A
`.confidence` suffix reads how concentrated a choice or score answer was;
`noul` answers have no confidence, because the probability *is* the signal.

Because `when:` ANDs with `event`/`agent`/`tools`/`paths`/`commands`, adding a
judgment to an existing rule can only ever make it fire **less** often. That
makes narrowing a blunt rule with a judgment a strictly safe edit: it can
remove false positives, but it can never introduce a block that wasn't
already there. To express OR, write two rules.

### What it costs

hookmon first works out which rules match *lexically*, then asks only the
judgments those rules reference — all of them in a single request, since
System One evaluates questions in parallel. **If no matching rule has a
`when:` clause, no network call is made at all**, so a policy that uses only
`commands:`/`paths:` is exactly as fast as before.

Answers are cached on disk (default: 24h, in your user cache directory), so
the commands an agent repeats all day — `go build`, `git status` — are judged
once. Set `--typesafe-cache-ttl 0` to disable.

### Configuration

Set your API key as an **environment variable**, never as a flag and never in
the policy file:

```bash
export HOOKMON_TYPESAFE_API_KEY=...
```

The policy file is meant to be checked in and shared, and the hook command
line lives in `.claude/settings.json`, which is also checked in — a key in
either would be committed. hookmon never reads an API key from the policy
file. `~/.hookmon.yaml` works too; `chmod 600` it.

| Setting | Flag | Default |
| --- | --- | --- |
| `HOOKMON_TYPESAFE_API_KEY` | *(none, by design)* | unset — judgments never fire |
| `HOOKMON_TYPESAFE_ENDPOINT` | *(none)* | `https://api.typesafe.ai/v1/systemone` |
| `HOOKMON_TYPESAFE_MODEL` | `--typesafe-model` | `jev-latest` |
| `HOOKMON_TYPESAFE_TIMEOUT` | `--typesafe-timeout` | `1.5s` |
| `HOOKMON_TYPESAFE_CACHE_TTL` | `--typesafe-cache-ttl` | `24h` |
| `HOOKMON_TYPESAFE_CACHE_DIR` | `--typesafe-cache-dir` | user cache dir |
| `HOOKMON_TYPESAFE_SEND_CONTENT` | `--typesafe-send-content` | `false` |

### What leaves your machine

This is the one part of hookmon that talks to a third party, and only for
events that a `when:` rule already matched. hookmon sends the agent name, the
event name, the tool name, `cwd`, and the tool's `tool_input`.

**File and message content is stripped first.** The `content`, `new_string`,
`old_string`, `edits`, and `plan` fields are dropped, and every remaining
string is truncated. A `Write` to `.env` sends the *path*, never the secret —
judging what a call does needs the target, not the payload. `--typesafe-send-content`
lifts this if you want it; leave it off unless you have a reason.

### When judgments fail

A missing API key, a network error, a timeout, a non-2xx response, or a
missing answer all mean the `when:` clause **could not be evaluated**. The
rule then takes its `on-error` action:

- `allow` (the default) — the rule does not fire, exactly like a missing
  policy file. Fail-open, consistent with the rest of hookmon.
- `ask` — degrade to a confirmation prompt.
- `deny` — block.

hookmon always warns on stderr naming the judgments it skipped. Note the
trade-off honestly: with the default `allow`, a network blip silently stops a
`deny` rule from protecting anything. Use `on-error: ask` on the rules where
that matters.

`on-error` applies **only** when the clause was unevaluable — never when an
answer arrived and simply fell below the threshold.

### Tuning thresholds

Every `deny` written to `--policy-log-file` records the judgment that fired
and its value:

```json
{
  "command": "rm -r -f ./src",
  "action": "deny",
  "reason": "This command would irreversibly destroy work.",
  "judgment": "destroys_work",
  "judgment_value": 0.92,
  "judgment_condition": ">= 0.85"
}
```

Thresholds are an application decision, not something to inherit from an
example. Pick them against your own traffic.

### What should stay deterministic

A judgment narrows a blunt rule; it is not a sole line of defense. Keep exact
lookups in code:

- **The rule protecting the policy file itself.** A model-evaluated guard on
  its own guard fails open on a network blip.
- **Known-secret paths.** Keep `paths: [".env"]` as a deterministic rule
  alongside any `exposes_secrets` judgment — belt and braces.
- **Event, agent, and tool names.** Never probabilistic.
- **Anything where fail-open is unacceptable.** If "the network was down, so
  the rule didn't fire" is not survivable, that rule cannot have a `when:`.

**Fail-open by design**, matching every other error path in hookmon: a
missing policy file, a policy file that fails to parse, or a hook/tool that
matches no rule all behave exactly like no policy being configured at all —
they never block anything. Logging is unaffected either way: a denied call
still gets written to `--log-file` (the raw envelope) and, by default, to
`--policy-log-file` as a structured decision record; allowed and asked calls
are never written to `--policy-log-file`.

### Logging blocked calls

Every `deny` decision is additionally appended to `--policy-log-file` as a
structured JSON record, separate from the raw envelope written to
`--log-file`:

```json
{
  "time": "2026-09-18T12:00:00Z",
  "agent": "claudecode",
  "event": "PreToolUse",
  "tool": "Bash",
  "path": "",
  "command": "echo hi",
  "action": "deny",
  "reason": "Direct Bash calls are blocked by hookmon policy."
}
```

Configure the path with `--policy-log-file`, `HOOKMON_POLICY_LOG_FILE`, or
`policy-log-file:` in `.hookmon.yaml` (default: `.hookmon-policy.log` in the
current directory). Set it to an empty string to disable this log entirely.
Only `deny` decisions are recorded — `allow` and `ask` never write an entry.

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
