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

func TestLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hookmon.log")
	cfg := relay.Config{Agent: "cursor", LogFile: path}

	first := []byte(`{"hook_event_name":"sessionStart"}`)
	if err := relay.Log(cfg, first); err != nil {
		t.Fatalf("Log: %v", err)
	}

	cfg.Agent = "claudecode"
	second := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	if err := relay.Log(cfg, second); err != nil {
		t.Fatalf("Log: %v", err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)

	firstIdx := indexOf(t, got, `"agent": "cursor"`)
	secondIdx := indexOf(t, got, `"agent": "claudecode"`)
	if firstIdx >= secondIdx {
		t.Fatalf("expected cursor envelope before claudecode envelope, got:\n%s", got)
	}
	for _, want := range []string{
		`"hook_event_name": "sessionStart"`,
		`"hook_event_name": "PreToolUse"`,
		`"tool_name": "Bash"`,
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("log missing %q:\n%s", want, got)
		}
	}
}

func indexOf(t *testing.T, s, substr string) int {
	t.Helper()
	i := bytes.Index([]byte(s), []byte(substr))
	if i < 0 {
		t.Fatalf("missing %q in:\n%s", substr, s)
	}
	return i
}

func TestLogInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hookmon.log")
	err := relay.Log(relay.Config{Agent: "cursor", LogFile: path}, []byte("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("expected no log file to be created for invalid JSON")
	}
}

func TestLogNoFileConfigured(t *testing.T) {
	payload := []byte(`{"hook_event_name":"stop"}`)
	if err := relay.Log(relay.Config{Agent: "cursor"}, payload); err != nil {
		t.Fatalf("Log: %v", err)
	}
}

func TestLogConcurrentWriters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hookmon.log")
	cfg := relay.Config{Agent: "cursor", LogFile: path}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			payload := []byte(`{"hook_event_name":"preToolUse","tool_name":"Shell"}`)
			if err := relay.Log(cfg, payload); err != nil {
				t.Errorf("Log: %v", err)
			}
		}(i)
	}
	wg.Wait()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	count := 0
	for dec.More() {
		var env relay.Envelope
		if err := dec.Decode(&env); err != nil {
			t.Fatalf("corrupted log at entry %d: %v\nfull log:\n%s", count, err, b)
		}
		if env.Agent != "cursor" {
			t.Fatalf("entry %d: agent = %q", count, env.Agent)
		}
		count++
	}
	if count != n {
		t.Fatalf("expected %d envelopes, got %d", n, count)
	}
}

func TestEnvelopeMarshal(t *testing.T) {
	env := relay.Envelope{
		Agent:   "cursor",
		Payload: json.RawMessage(`{"hook_event_name":"stop"}`),
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back relay.Envelope
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Agent != "cursor" {
		t.Fatalf("agent = %q", back.Agent)
	}
}
