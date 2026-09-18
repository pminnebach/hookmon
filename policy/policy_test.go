package policy_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"hookmon/agent"
	"hookmon/policy"
)

func TestResolveNoRulesAllows(t *testing.T) {
	d := policy.Resolve(policy.Config{}, policy.Event{Name: "PreToolUse", Tool: "Bash"})
	if d.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", d.Action)
	}
}

func TestResolveDenyMatch(t *testing.T) {
	cfg := policy.Config{Rules: []policy.Rule{
		{Event: "PreToolUse", Tools: []string{"Bash"}, Action: "deny", Reason: "no bash"},
	}}
	d := policy.Resolve(cfg, policy.Event{Name: "PreToolUse", Tool: "Bash"})
	if d.Action != agent.Deny {
		t.Fatalf("action = %v, want Deny", d.Action)
	}
	if d.Reason != "no bash" {
		t.Fatalf("reason = %q", d.Reason)
	}
}

func TestResolveToolMismatchFallsThrough(t *testing.T) {
	cfg := policy.Config{Rules: []policy.Rule{
		{Event: "PreToolUse", Tools: []string{"Bash"}, Action: "deny"},
	}}
	d := policy.Resolve(cfg, policy.Event{Name: "PreToolUse", Tool: "Write"})
	if d.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", d.Action)
	}
}

func TestResolveEventMismatchFallsThrough(t *testing.T) {
	cfg := policy.Config{Rules: []policy.Rule{
		{Event: "PreToolUse", Tools: []string{"Bash"}, Action: "deny"},
	}}
	d := policy.Resolve(cfg, policy.Event{Name: "PostToolUse", Tool: "Bash"})
	if d.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", d.Action)
	}
}

func TestResolveAgentScopedRuleIgnoredForOtherAgent(t *testing.T) {
	cfg := policy.Config{Rules: []policy.Rule{
		{Event: "PreToolUse", Agent: "claudecode", Tools: []string{"Bash"}, Action: "deny"},
	}}
	d := policy.Resolve(cfg, policy.Event{Agent: "cursor", Name: "PreToolUse", Tool: "Bash"})
	if d.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow (rule scoped to a different agent)", d.Action)
	}
}

func TestResolvePrecedenceDenyBeatsAllow(t *testing.T) {
	cfg := policy.Config{Rules: []policy.Rule{
		{Event: "PreToolUse", Tools: []string{"Bash"}, Action: "allow"},
		{Event: "PreToolUse", Tools: []string{"Bash"}, Action: "deny", Reason: "stricter rule wins"},
	}}
	d := policy.Resolve(cfg, policy.Event{Name: "PreToolUse", Tool: "Bash"})
	if d.Action != agent.Deny {
		t.Fatalf("action = %v, want Deny", d.Action)
	}
}

func TestResolveDefaultActionAppliesOnNoMatch(t *testing.T) {
	cfg := policy.Config{DefaultAction: "deny"}
	d := policy.Resolve(cfg, policy.Event{Name: "PreToolUse", Tool: "Bash"})
	if d.Action != agent.Deny {
		t.Fatalf("action = %v, want Deny (default-action)", d.Action)
	}
}

func TestParseEventClaudeCodePayload(t *testing.T) {
	payload := []byte(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	evt := policy.ParseEvent("claudecode", payload)
	want := policy.Event{Agent: "claudecode", Name: "PreToolUse", Tool: "Bash"}
	if evt != want {
		t.Fatalf("evt = %+v, want %+v", evt, want)
	}
}

func TestParseEventCursorPayload(t *testing.T) {
	payload := []byte(`{"hook_event_name":"preToolUse","tool_name":"Shell"}`)
	evt := policy.ParseEvent("cursor", payload)
	want := policy.Event{Agent: "cursor", Name: "preToolUse", Tool: "Shell"}
	if evt != want {
		t.Fatalf("evt = %+v, want %+v", evt, want)
	}
}

func TestParseEventMalformedPayloadYieldsZeroValues(t *testing.T) {
	evt := policy.ParseEvent("cursor", []byte("not-json"))
	want := policy.Event{Agent: "cursor"}
	if evt != want {
		t.Fatalf("evt = %+v, want %+v", evt, want)
	}
}

func TestLoadMissingFileIsNotAnError(t *testing.T) {
	cfg, found, err := policy.Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if found {
		t.Fatal("found = true, want false")
	}
	if len(cfg.Rules) != 0 {
		t.Fatalf("cfg = %+v, want zero value", cfg)
	}
}

func TestLoadMalformedYAMLErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("not: [valid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, found, err := policy.Load(path)
	if err == nil {
		t.Fatal("expected a parse error")
	}
	if !found {
		t.Fatal("found = false, want true (the file exists, just fails to parse)")
	}
}

func TestLoadParsesRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	yaml := `
rules:
  - event: PreToolUse
    agent: claudecode
    tools: ["Bash"]
    action: deny
    reason: "no bash"

default-action: allow
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, found, err := policy.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !found {
		t.Fatal("found = false, want true")
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("rules = %+v", cfg.Rules)
	}
	r := cfg.Rules[0]
	if r.Event != "PreToolUse" || r.Agent != "claudecode" || r.Action != "deny" || r.Reason != "no bash" {
		t.Fatalf("rule = %+v", r)
	}
	if len(r.Tools) != 1 || r.Tools[0] != "Bash" {
		t.Fatalf("tools = %+v", r.Tools)
	}
}

func TestLoadConcurrentReaders(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	yaml := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: deny
`
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			cfg, found, err := policy.Load(path)
			if err != nil {
				t.Errorf("Load: %v", err)
			}
			if !found {
				t.Error("found = false, want true")
			}
			if len(cfg.Rules) != 1 {
				t.Errorf("rules = %+v", cfg.Rules)
			}
		}()
	}
	wg.Wait()
}
