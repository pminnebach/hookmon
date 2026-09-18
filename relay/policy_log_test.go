package relay_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"hookmon/relay"
)

func TestLogPolicyDecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.log")
	cfg := relay.Config{PolicyLogFile: path}

	d := relay.PolicyDecision{
		Time:   "2026-09-18T12:00:00Z",
		Agent:  "claudecode",
		Event:  "PreToolUse",
		Tool:   "Bash",
		Path:   "",
		Action: "deny",
		Reason: "blocked by test policy",
	}
	if err := relay.LogPolicyDecision(cfg, d); err != nil {
		t.Fatalf("LogPolicyDecision: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var back relay.PolicyDecision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("decoding policy log: %v\n%s", err, b)
	}
	if back != d {
		t.Fatalf("got %+v, want %+v", back, d)
	}
	for _, want := range []string{
		`"time": "2026-09-18T12:00:00Z"`,
		`"agent": "claudecode"`,
		`"event": "PreToolUse"`,
		`"tool": "Bash"`,
		`"action": "deny"`,
		`"reason": "blocked by test policy"`,
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("policy log missing %q:\n%s", want, b)
		}
	}
}

func TestLogPolicyDecisionAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.log")
	cfg := relay.Config{PolicyLogFile: path}

	first := relay.PolicyDecision{Agent: "cursor", Tool: "Shell", Action: "deny"}
	if err := relay.LogPolicyDecision(cfg, first); err != nil {
		t.Fatalf("LogPolicyDecision: %v", err)
	}
	second := relay.PolicyDecision{Agent: "claudecode", Tool: "Bash", Action: "deny"}
	if err := relay.LogPolicyDecision(cfg, second); err != nil {
		t.Fatalf("LogPolicyDecision: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	firstIdx := indexOf(t, got, `"tool": "Shell"`)
	secondIdx := indexOf(t, got, `"tool": "Bash"`)
	if firstIdx >= secondIdx {
		t.Fatalf("expected first entry before second, got:\n%s", got)
	}
}

func TestLogPolicyDecisionNoFileConfigured(t *testing.T) {
	if err := relay.LogPolicyDecision(relay.Config{}, relay.PolicyDecision{Action: "deny"}); err != nil {
		t.Fatalf("LogPolicyDecision: %v", err)
	}
}

func TestLogPolicyDecisionConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.log")
	cfg := relay.Config{PolicyLogFile: path}

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			d := relay.PolicyDecision{Agent: "cursor", Tool: "Shell", Action: "deny"}
			if err := relay.LogPolicyDecision(cfg, d); err != nil {
				t.Errorf("LogPolicyDecision: %v", err)
			}
		}()
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	count := 0
	for dec.More() {
		var d relay.PolicyDecision
		if err := dec.Decode(&d); err != nil {
			t.Fatalf("corrupted policy log at entry %d: %v\nfull log:\n%s", count, err, b)
		}
		if d.Action != "deny" {
			t.Fatalf("entry %d: action = %q", count, d.Action)
		}
		count++
	}
	if count != n {
		t.Fatalf("expected %d entries, got %d", n, count)
	}
}

func TestPolicyDecisionMarshal(t *testing.T) {
	d := relay.PolicyDecision{
		Time:   "2026-09-18T12:00:00Z",
		Agent:  "cursor",
		Event:  "preToolUse",
		Tool:   "Shell",
		Path:   "/tmp/x",
		Action: "deny",
		Reason: "test",
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back relay.PolicyDecision
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != d {
		t.Fatalf("got %+v, want %+v", back, d)
	}
}
