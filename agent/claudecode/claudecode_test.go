package claudecode_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"hookmon/agent"
	_ "hookmon/agent/claudecode"
)

func TestLookupClaudeCode(t *testing.T) {
	p, err := agent.Lookup("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name() != "claudecode" {
		t.Fatalf("Name = %q", p.Name())
	}
	if len(p.Events()) < 30 {
		t.Fatalf("expected all Claude Code hook events, got %d", len(p.Events()))
	}
}

func TestAcknowledge(t *testing.T) {
	p, err := agent.Lookup("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := p.Acknowledge(&buf); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "{}\n" {
		t.Fatalf("ack = %q", buf.String())
	}
}

func TestHooksConfig(t *testing.T) {
	p, err := agent.Lookup("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	const sendCmd = "${CLAUDE_PROJECT_DIR}/hookmon --agent claudecode"
	raw, err := p.HooksConfig(sendCmd)
	if err != nil {
		t.Fatal(err)
	}

	var cfg struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}

	// Events known (from https://code.claude.com/docs/en/hooks) to support
	// a matcher; every other event in p.Events() must omit it.
	matcherEvents := map[string]bool{
		"SessionStart": true, "Setup": true, "UserPromptExpansion": true,
		"PreToolUse": true, "PermissionRequest": true, "PermissionDenied": true,
		"PostToolUse": true, "PostToolUseFailure": true, "Notification": true,
		"SubagentStart": true, "SubagentStop": true, "StopFailure": true,
		"InstructionsLoaded": true, "ConfigChange": true, "DirectoryAdded": true,
		"FileChanged": true, "PreCompact": true, "PostCompact": true,
		"PreModelSwitch": true, "PostModelSwitch": true, "Elicitation": true,
		"ElicitationResult": true, "SessionEnd": true,
	}

	for _, e := range p.Events() {
		entries, ok := cfg.Hooks[e]
		if !ok || len(entries) == 0 {
			t.Fatalf("missing hook event %q", e)
		}
		entry := entries[0]
		if len(entry.Hooks) == 0 || entry.Hooks[0].Type != "command" {
			t.Fatalf("event %s: hooks[0].type = %+v", e, entry.Hooks)
		}
		if entry.Hooks[0].Command != sendCmd {
			t.Fatalf("event %s: command = %q", e, entry.Hooks[0].Command)
		}
		wantMatcher := ""
		if matcherEvents[e] {
			wantMatcher = "*"
		}
		if entry.Matcher != wantMatcher {
			t.Fatalf("event %s: matcher = %q, want %q", e, entry.Matcher, wantMatcher)
		}
	}
}
