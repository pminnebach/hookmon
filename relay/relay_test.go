package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"hookmon/relay"
)

func TestSendListenRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var buf bytes.Buffer
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = relay.Listen(ctx, relay.Config{Addr: addr}, &safeWriter{mu: &mu, w: &buf})
	}()

	// Wait until listener is up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	payload := []byte(`{"hook_event_name":"preToolUse","tool_name":"Shell"}`)
	errOut := &bytes.Buffer{}
	if err := relay.Send(t.Context(), relay.Config{Addr: addr, Agent: "cursor"}, payload, errOut); err != nil {
		t.Fatalf("Send: %v (stderr=%s)", err, errOut)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := buf.String()
		mu.Unlock()
		if bytes.Contains([]byte(got), []byte(`"agent": "cursor"`)) &&
			bytes.Contains([]byte(got), []byte(`"hook_event_name": "preToolUse"`)) {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	got := buf.String()
	mu.Unlock()
	t.Fatalf("listen output missing envelope:\n%s", got)
}

func TestSendListenRoundTrip_ClaudeCode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	var buf bytes.Buffer
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = relay.Listen(ctx, relay.Config{Addr: addr}, &safeWriter{mu: &mu, w: &buf})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cfg := relay.Config{Addr: addr, Agent: "claudecode"}
	errOut := &bytes.Buffer{}

	preToolUse := []byte(`{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"cwd":"/workspace","transcript_path":"/tmp/t.json"}`)
	if err := relay.Send(t.Context(), cfg, preToolUse, errOut); err != nil {
		t.Fatalf("Send(PreToolUse): %v (stderr=%s)", err, errOut)
	}
	waitForOutput(t, &mu, &buf, `"agent": "claudecode"`, `"hook_event_name": "PreToolUse"`, `"tool_name": "Bash"`)

	postToolUse := []byte(`{"session_id":"test","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"echo hi"},"tool_response":"hi","cwd":"/workspace","transcript_path":"/tmp/t.json"}`)
	if err := relay.Send(t.Context(), cfg, postToolUse, errOut); err != nil {
		t.Fatalf("Send(PostToolUse): %v (stderr=%s)", err, errOut)
	}
	waitForOutput(t, &mu, &buf, `"agent": "claudecode"`, `"hook_event_name": "PostToolUse"`, `"tool_response"`)

	cancel()
	<-done
}

func waitForOutput(t *testing.T, mu *sync.Mutex, buf *bytes.Buffer, want ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := buf.String()
		mu.Unlock()
		ok := true
		for _, w := range want {
			if !bytes.Contains([]byte(got), []byte(w)) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	got := buf.String()
	mu.Unlock()
	t.Fatalf("listen output missing %v:\n%s", want, got)
}

func TestListenToFile(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	f, err := os.CreateTemp(t.TempDir(), "hookmon-*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer f.Close()
		_ = relay.Listen(ctx, relay.Config{Addr: addr}, f)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	payload := []byte(`{"hook_event_name":"sessionStart"}`)
	if err := relay.Send(t.Context(), relay.Config{Addr: addr, Agent: "cursor"}, payload, io.Discard); err != nil {
		t.Fatalf("Send: %v", err)
	}

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(`"agent": "cursor"`)) &&
			bytes.Contains(b, []byte(`"hook_event_name": "sessionStart"`)) {
			cancel()
			<-done
			return
		}
		time.Sleep(20 * time.Millisecond)
	}

	b, _ := os.ReadFile(path)
	cancel()
	<-done
	t.Fatalf("log file missing envelope:\n%s", b)
}

func TestSendInvalidJSON(t *testing.T) {
	errOut := &bytes.Buffer{}
	err := relay.Send(t.Context(), relay.Config{Addr: "127.0.0.1:1", Agent: "cursor"}, []byte("not-json"), errOut)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
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

type safeWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
