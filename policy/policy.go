// Package policy resolves allow/deny/ask decisions for hook events against
// a shared, checked-in policy file.
//
// Every hookmon invocation is a fresh, short-lived process (no daemon, no
// shared memory), so Load re-reads and re-parses the policy file on every
// call. This keeps the model consistent with the rest of hookmon: an edit to
// the policy file takes effect on the very next hook invocation, with
// nothing to restart or signal.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"go.yaml.in/yaml/v3"

	"hookmon/agent"
	"hookmon/judge"
)

// Rule matches a hook event (optionally scoped to one agent, one or more
// exact tool names, one or more file path patterns, and one or more command
// substrings) and states the action to take when it matches. Tools, Paths,
// Commands, and When each AND with the rest of the rule; an empty Tools,
// Paths, Commands, or When means that filter is trivially satisfied.
//
// Because When ANDs rather than ORs, adding a judgment to an existing rule
// can only ever make it fire less often. That makes "narrow this blunt rule
// with a judgment" a strictly safe edit: it can reduce false positives, but
// it can never introduce a block that wasn't already there.
type Rule struct {
	Event    string   `yaml:"event"`
	Agent    string   `yaml:"agent,omitempty"`
	Tools    []string `yaml:"tools,omitempty"`
	Paths    []string `yaml:"paths,omitempty"`
	Commands []string `yaml:"commands,omitempty"`
	// When maps judgment IDs (optionally suffixed ".confidence") to the
	// condition each must satisfy, e.g. {"destroys_work": ">= 0.85"}.
	When map[string]string `yaml:"when,omitempty"`
	// OnError is the action this rule contributes when its When clause
	// cannot be evaluated — no API key, a network failure, a timeout, or a
	// missing answer. "allow" (the default) means the rule simply does not
	// fire, matching every other fail-open path in hookmon.
	OnError string `yaml:"on-error,omitempty"`
	Action  string `yaml:"action"`
	Reason  string `yaml:"reason,omitempty"`
}

// Config is the parsed contents of a policy file.
type Config struct {
	Rules []Rule `yaml:"rules"`
	// Judgments declares the semantic questions rules may reference from a
	// When clause. Declared once here, asked once per hook event.
	Judgments map[string]judge.Question `yaml:"judgments,omitempty"`
	// DefaultAction applies when no rule matches. Empty means "allow".
	DefaultAction string `yaml:"default-action,omitempty"`
}

// Load reads and parses the YAML policy file at path.
//
// A missing file is not an error: found is false and cfg is the zero
// Config, which Resolve treats identically to "no policy configured" (i.e.
// allow everything). Callers should likewise treat a non-nil err as
// fail-open: log it and proceed as if no policy were configured, consistent
// with every other error path in hookmon.
func Load(path string) (cfg Config, found bool, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, false, nil
		}
		return Config{}, false, fmt.Errorf("read policy file %s: %w", path, err)
	}

	// Decode strictly. yaml.Unmarshal ignores unknown fields, which turns a
	// policy written for a newer hookmon into a silently different policy:
	// a binary predating `when:` reads a judgment-guarded rule as an
	// unconditional deny, blocking everything and reporting a reason that
	// misleads about the cause. Failing the parse instead routes through
	// this function's fail-open contract, so a version skew allows
	// everything and says so on stderr.
	//
	// This cannot rescue binaries already built — they have no strict
	// decoding to begin with — so upgrading hookmon before adopting a policy
	// that uses newer fields is still required.
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, true, fmt.Errorf("parse policy file %s: %w", path, err)
	}
	return cfg, true, nil
}

// Event is the generic slice of a hook payload that policy matching needs.
// Both Claude Code and Cursor use "hook_event_name" and "tool_name" as the
// relevant JSON keys for tool-related events, so one parse covers both. Path
// and Command are only populated for Claude Code today (tool_input.file_path
// and tool_input.command respectively); an agent without a known field
// simply yields an empty Path/Command, which never matches a rule's Paths or
// Commands filter.
// ToolInput carries the whole raw tool_input as JSON text, for judgments.
// It is a string rather than a json.RawMessage so that Event stays
// comparable with ==, which the tests rely on.
type Event struct {
	Agent     string
	Name      string
	Tool      string
	Path      string
	Command   string
	Cwd       string
	ToolInput string
}

// ParseEvent extracts the fields policy needs from a raw hook payload.
// It never errors: a malformed or field-less payload just yields zero
// values, which match no rule and therefore fall open to Resolve's default.
func ParseEvent(agentName string, payload []byte) Event {
	var fields struct {
		HookEventName string          `json:"hook_event_name"`
		ToolName      string          `json:"tool_name"`
		Cwd           string          `json:"cwd"`
		ToolInput     json.RawMessage `json:"tool_input"`
	}
	_ = json.Unmarshal(payload, &fields)

	// Path and Command keep their own narrow decode so the lexical filters
	// behave byte-identically to before ToolInput existed.
	var input struct {
		FilePath string `json:"file_path"`
		Command  string `json:"command"`
	}
	if len(fields.ToolInput) > 0 {
		_ = json.Unmarshal(fields.ToolInput, &input)
	}

	return Event{
		Agent:     agentName,
		Name:      fields.HookEventName,
		Tool:      fields.ToolName,
		Path:      input.FilePath,
		Command:   input.Command,
		Cwd:       fields.Cwd,
		ToolInput: string(fields.ToolInput),
	}
}

// Result carries the outcome of the judgment step. A zero Result means
// judgments were never attempted, which is what every fail-open path and
// every judgment-unaware caller produces.
type Result struct {
	Answers judge.Answers
	// Err is set when a judgment step that did run failed as a whole
	// (network error, timeout, non-2xx). Rules with a When clause then take
	// their OnError action.
	Err error
	// Attempted reports that the judgment step actually ran for this event.
	//
	// False means judgments are not configured at all — no API key, or a
	// caller like Resolve that supplies none — and When clauses are then
	// inert: OnError does not apply. OnError exists for a configured
	// judgment failing at runtime, not for the absence of one. Without this
	// distinction, a policy carrying `on-error: ask` would prompt on every
	// matching call for any teammate who has no key, making a shared policy
	// unusable.
	Attempted bool
}

// Outcome is a resolved decision plus the provenance needed to log and tune
// it. It embeds agent.Decision, so Action and Reason read through directly.
type Outcome struct {
	agent.Decision
	// Judgment, Value and Condition describe the answer that satisfied the
	// winning rule's When clause, when one did.
	Judgment  string
	Value     float64
	Condition string
}

// Resolve evaluates every rule in cfg against evt, without judgments. Rules
// carrying a When clause take their OnError action, which by default means
// they do not fire.
func Resolve(cfg Config, evt Event) agent.Decision {
	return ResolveWith(cfg, evt, Result{}).Decision
}

// ResolveWith evaluates every rule in cfg against evt and returns the
// resulting Outcome. When multiple rules match, Deny takes precedence over
// Ask, which takes precedence over Allow — the same precedence Claude Code
// itself documents for multiple PreToolUse hooks. When no rule matches,
// cfg.DefaultAction applies (allow if unset).
func ResolveWith(cfg Config, evt Event, res Result) Outcome {
	best := Outcome{Decision: agent.Decision{Action: parseAction(cfg.DefaultAction)}}

	for _, r := range cfg.Rules {
		if !ruleMatches(r, evt) {
			continue
		}
		action, h, fires := ruleAction(r, res)
		if !fires || action <= best.Action {
			continue
		}
		best = Outcome{
			Decision:  agent.Decision{Action: action, Reason: r.Reason},
			Judgment:  h.ID,
			Value:     h.Value,
			Condition: h.Condition,
		}
	}
	return best
}

// Candidates returns every rule whose lexical filters (event, agent, tools,
// paths, commands) match evt, ignoring When entirely.
//
// This is the first half of the two-phase evaluation: it determines which
// judgments are worth asking about, so exactly one API request is made
// carrying exactly the questions some candidate rule needs — and none at all
// when no candidate has a When clause.
func Candidates(cfg Config, evt Event) []Rule {
	var out []Rule
	for _, r := range cfg.Rules {
		if ruleMatches(r, evt) {
			out = append(out, r)
		}
	}
	return out
}

// ruleAction reports the action a lexically-matching rule contributes, and
// whether it contributes one at all.
func ruleAction(r Rule, res Result) (agent.Action, hit, bool) {
	if len(r.When) == 0 {
		return parseAction(r.Action), hit{}, true
	}
	if !res.Attempted {
		// Judgments are not configured, so this rule has nothing to say.
		// Deliberately not the on-error path: see Result.Attempted.
		return agent.Allow, hit{}, false
	}

	ok, h, err := evalWhen(r.When, res.Answers)
	switch {
	case err != nil || res.Err != nil:
		// Unevaluable: fall back to on-error. An omitted on-error is
		// "allow", i.e. the rule does not fire.
		onErr := parseAction(r.OnError)
		return onErr, hit{}, onErr != agent.Allow
	case !ok:
		return agent.Allow, hit{}, false
	default:
		return parseAction(r.Action), h, true
	}
}

func ruleMatches(r Rule, evt Event) bool {
	if r.Event != evt.Name {
		return false
	}
	if r.Agent != "" && r.Agent != evt.Agent {
		return false
	}
	if len(r.Tools) > 0 && !toolMatches(r.Tools, evt.Tool) {
		return false
	}
	if len(r.Paths) > 0 && !pathsMatch(r.Paths, evt.Path) {
		return false
	}
	if len(r.Commands) > 0 && !commandsMatch(r.Commands, evt.Command) {
		return false
	}
	return true
}

func toolMatches(tools []string, tool string) bool {
	for _, t := range tools {
		if t == tool {
			return true
		}
	}
	return false
}

// commandsMatch reports whether any pattern is a substring of command. An
// empty command never matches anything, regardless of pattern — that's how
// a rule with a Commands filter fails open against an event with no known
// command (e.g. a non-Bash tool, or an agent that doesn't report one).
// Matching is a plain substring test, not a glob or regex, so a pattern like
// "git push" also matches "git push --force" or "git push origin main".
func commandsMatch(patterns []string, command string) bool {
	if command == "" {
		return false
	}
	for _, pattern := range patterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
}

func pathsMatch(patterns []string, p string) bool {
	for _, pattern := range patterns {
		if pathMatches(pattern, p) {
			return true
		}
	}
	return false
}

// pathMatches reports whether pattern matches path, using gitignore-style
// component matching rather than a substring test (so a pattern like ".env"
// never wrongly matches a path like "foo.envelope.txt"). An empty path never
// matches anything, regardless of pattern — that's how a rule with a Paths
// filter fails open against an event with no known file path.
//
//   - A pattern with no "/" (e.g. ".env", "*.env") matches the path's final
//     component only, anchoring the pattern at any depth in the tree.
//   - A pattern ending in "/" (e.g. ".git/") matches if any non-final
//     component of the path equals the pattern (directory anchor).
//   - A pattern containing "/" but not ending in it (e.g. "config/.env")
//     matches if the path's trailing components equal the pattern's
//     components in sequence (an anchored suffix match).
//
// Each component/pattern segment is compared with exact string equality
// unless the segment contains a glob metacharacter (*, ?, [), in which case
// it's compared with path.Match. There is no support for "**", negation, or
// filesystem/symlink resolution — matching is purely lexical against
// whatever string the hook payload provided.
func pathMatches(pattern, p string) bool {
	components := splitPathComponents(p)
	if len(components) == 0 {
		return false
	}

	switch {
	case strings.HasSuffix(pattern, "/"):
		dir := strings.TrimSuffix(pattern, "/")
		for _, c := range components[:len(components)-1] {
			if segmentMatches(dir, c) {
				return true
			}
		}
		return false

	case strings.Contains(pattern, "/"):
		patternParts := splitPathComponents(pattern)
		if len(patternParts) == 0 || len(patternParts) > len(components) {
			return false
		}
		suffix := components[len(components)-len(patternParts):]
		for i, part := range patternParts {
			if !segmentMatches(part, suffix[i]) {
				return false
			}
		}
		return true

	default:
		return segmentMatches(pattern, components[len(components)-1])
	}
}

func segmentMatches(pattern, segment string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == segment
	}
	ok, err := path.Match(pattern, segment)
	return err == nil && ok
}

func splitPathComponents(p string) []string {
	normalized := strings.ReplaceAll(p, `\`, "/")
	parts := strings.Split(normalized, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseAction(s string) agent.Action {
	switch s {
	case "deny":
		return agent.Deny
	case "ask":
		return agent.Ask
	default:
		return agent.Allow
	}
}
