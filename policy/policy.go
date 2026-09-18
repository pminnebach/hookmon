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
	"encoding/json"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"

	"hookmon/agent"
)

// Rule matches a hook event (optionally scoped to one agent and one or more
// exact tool names) and states the action to take when it matches.
type Rule struct {
	Event  string   `yaml:"event"`
	Agent  string   `yaml:"agent,omitempty"`
	Tools  []string `yaml:"tools,omitempty"`
	Action string   `yaml:"action"`
	Reason string   `yaml:"reason,omitempty"`
}

// Config is the parsed contents of a policy file.
type Config struct {
	Rules []Rule `yaml:"rules"`
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

	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, true, fmt.Errorf("parse policy file %s: %w", path, err)
	}
	return cfg, true, nil
}

// Event is the generic slice of a hook payload that policy matching needs.
// Both Claude Code and Cursor use "hook_event_name" and "tool_name" as the
// relevant JSON keys for tool-related events, so one parse covers both.
type Event struct {
	Agent string
	Name  string
	Tool  string
}

// ParseEvent extracts the fields policy needs from a raw hook payload.
// It never errors: a malformed or field-less payload just yields zero
// values, which match no rule and therefore fall open to Resolve's default.
func ParseEvent(agentName string, payload []byte) Event {
	var fields struct {
		HookEventName string `json:"hook_event_name"`
		ToolName      string `json:"tool_name"`
	}
	_ = json.Unmarshal(payload, &fields)
	return Event{Agent: agentName, Name: fields.HookEventName, Tool: fields.ToolName}
}

// Resolve evaluates every rule in cfg against evt and returns the resulting
// Decision. When multiple rules match, Deny takes precedence over Ask, which
// takes precedence over Allow — the same precedence Claude Code itself
// documents for multiple PreToolUse hooks. When no rule matches, cfg.
// DefaultAction applies (allow if unset).
func Resolve(cfg Config, evt Event) agent.Decision {
	best := agent.Decision{Action: parseAction(cfg.DefaultAction)}

	for _, r := range cfg.Rules {
		if !ruleMatches(r, evt) {
			continue
		}
		action := parseAction(r.Action)
		if action > best.Action {
			best = agent.Decision{Action: action, Reason: r.Reason}
		}
	}
	return best
}

func ruleMatches(r Rule, evt Event) bool {
	if r.Event != evt.Name {
		return false
	}
	if r.Agent != "" && r.Agent != evt.Agent {
		return false
	}
	if len(r.Tools) == 0 {
		return true
	}
	for _, t := range r.Tools {
		if t == evt.Tool {
			return true
		}
	}
	return false
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
