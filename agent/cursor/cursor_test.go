package cursor_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"hookmon/agent"
	_ "hookmon/agent/cursor"
)

func TestLookupCursor(t *testing.T) {
	p, err := agent.Lookup("cursor")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "cursor" {
		t.Fatalf("Name = %q", p.Name())
	}
	if len(p.Events()) < 10 {
		t.Fatalf("expected many events, got %d", len(p.Events()))
	}
}

func TestAcknowledge(t *testing.T) {
	p, err := agent.Lookup("cursor")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := p.Acknowledge(&buf, "stop", agent.Decision{}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "{}\n" {
		t.Fatalf("ack = %q", buf.String())
	}
}

func TestAcknowledgeDenyPreToolUse(t *testing.T) {
	p, err := agent.Lookup("cursor")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	decision := agent.Decision{Action: agent.Deny, Reason: "blocked by policy"}
	if err := p.Acknowledge(&buf, "preToolUse", decision); err != nil {
		t.Fatal(err)
	}

	var out struct {
		Permission   string `json:"permission"`
		UserMessage  string `json:"user_message"`
		AgentMessage string `json:"agent_message"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal ack: %v\nack = %q", err, buf.String())
	}
	if out.Permission != "deny" {
		t.Fatalf("permission = %q", out.Permission)
	}
	if out.UserMessage != "blocked by policy" || out.AgentMessage != "blocked by policy" {
		t.Fatalf("messages = %+v", out)
	}
}

func TestAcknowledgeDenyUnsupportedEventStaysNoop(t *testing.T) {
	p, err := agent.Lookup("cursor")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	decision := agent.Decision{Action: agent.Deny, Reason: "should be ignored"}
	if err := p.Acknowledge(&buf, "stop", decision); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "{}\n" {
		t.Fatalf("ack = %q, want {}\\n (stop doesn't support permission)", buf.String())
	}
}

func TestHooksConfig(t *testing.T) {
	p, err := agent.Lookup("cursor")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := p.HooksConfig("/workspace/hookmon --agent cursor")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Version int                            `json:"version"`
		Hooks   map[string][]map[string]string `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 {
		t.Fatalf("version = %d", cfg.Version)
	}
	for _, e := range p.Events() {
		entries, ok := cfg.Hooks[e]
		if !ok || len(entries) == 0 {
			t.Fatalf("missing hook event %q", e)
		}
		if entries[0]["command"] != "/workspace/hookmon --agent cursor" {
			t.Fatalf("command for %s = %q", e, entries[0]["command"])
		}
	}
}
