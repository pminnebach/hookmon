package cmd_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hookmon/cmd"
)

// TestRootCmdLogFile exercises the actual CLI wiring (flag parsing -> Viper
// decode -> relay.Log), not just the lower-level relay.Log function.
func TestRootCmdLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hookmon.log")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--log-file", path})
	root.SetIn(strings.NewReader(`{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"Bash"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	for _, want := range []string{
		`"agent": "claudecode"`,
		`"hook_event_name": "PreToolUse"`,
		`"tool_name": "Bash"`,
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("log file missing %q:\n%s", want, b)
		}
	}
}

// TestRootCmdNoLogFile confirms hookmon still acknowledges and exits
// cleanly when logging isn't configured (fail-open, no-op).
func TestRootCmdNoLogFile(t *testing.T) {
	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "cursor"})
	root.SetIn(strings.NewReader(`{"hook_event_name":"stop"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}
}

// TestRootCmdUnknownAgent confirms an unregistered agent still acknowledges
// instead of failing the hook.
func TestRootCmdUnknownAgent(t *testing.T) {
	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "does-not-exist"})
	root.SetIn(strings.NewReader(`{"hook_event_name":"stop"}`))

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}
	if !strings.Contains(stderr.String(), "does-not-exist") {
		t.Fatalf("stderr = %q, want mention of unknown agent", stderr.String())
	}
}
