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

// TestRootCmdNoPolicyFileFailsOpen confirms hookmon still allows tool calls
// when no --policy-file is configured (the default path doesn't exist in a
// fresh temp dir).
func TestRootCmdNoPolicyFileFailsOpen(t *testing.T) {
	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", filepath.Join(t.TempDir(), "missing.yaml")})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}
}

// TestRootCmdPolicyDeniesTool confirms a matching deny rule in the policy
// file actually blocks the tool call via the provider's decision shape.
func TestRootCmdPolicyDeniesTool(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: deny
    reason: "blocked by test policy"
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "hookmon.log")
	policyLogPath := filepath.Join(t.TempDir(), "policy.log")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath, "--log-file", logPath, "--policy-log-file", policyLogPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a deny decision", stdout.String())
	}

	// The call must still be logged even though it was denied.
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading log file: %v", err)
	}
	if !bytes.Contains(b, []byte(`"tool_name": "Bash"`)) {
		t.Fatalf("log file missing denied call:\n%s", b)
	}

	// The denial must also be recorded in the policy log.
	pb, err := os.ReadFile(policyLogPath)
	if err != nil {
		t.Fatalf("reading policy log file: %v", err)
	}
	for _, want := range []string{
		`"agent": "claudecode"`,
		`"event": "PreToolUse"`,
		`"tool": "Bash"`,
		`"command": "git push origin main"`,
		`"action": "deny"`,
		`"reason": "blocked by test policy"`,
	} {
		if !bytes.Contains(pb, []byte(want)) {
			t.Fatalf("policy log missing %q:\n%s", want, pb)
		}
	}
}

// TestRootCmdPolicyAllowsUnmatchedTool confirms a policy file with rules
// that don't match the incoming tool still allows it.
func TestRootCmdPolicyAllowsUnmatchedTool(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: deny
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Write"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}
}

// TestRootCmdPolicyDeniesPathMatch confirms a paths-scoped rule blocks a
// tool call whose tool_input.file_path matches, end to end through
// ParseEvent -> Resolve -> Acknowledge.
func TestRootCmdPolicyDeniesPathMatch(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Read", "Write"]
    paths: [".env"]
    action: deny
    reason: "blocked by test policy"
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	policyLogPath := filepath.Join(t.TempDir(), "policy.log")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath, "--policy-log-file", policyLogPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/user/project/.env"}}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a deny decision", stdout.String())
	}
}

// TestRootCmdPolicyAllowsPathMismatch confirms the same rule doesn't fire
// against an unrelated file, and doesn't false-positive on a filename that
// merely contains ".env" as a substring.
func TestRootCmdPolicyAllowsPathMismatch(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Read", "Write"]
    paths: [".env"]
    action: deny
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/user/project/foo.envelope.txt"}}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}
}

// TestRootCmdMalformedPolicyFailsOpen confirms a policy file that fails to
// parse doesn't block anything — it's treated as if no policy existed.
func TestRootCmdMalformedPolicyFailsOpen(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte("not: [valid yaml"), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if stdout.String() != "{}\n" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "{}\n")
	}
	if !strings.Contains(stderr.String(), "policy") {
		t.Fatalf("stderr = %q, want mention of the policy parse error", stderr.String())
	}
}

// TestRootCmdPolicyLogSkippedOnAllow confirms an allowed call (no matching
// rule) never creates the policy log file.
func TestRootCmdPolicyLogSkippedOnAllow(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: deny
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	policyLogPath := filepath.Join(t.TempDir(), "policy.log")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath, "--policy-log-file", policyLogPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Write"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := os.Stat(policyLogPath); !os.IsNotExist(err) {
		t.Fatalf("expected no policy log file for an allowed call, stat err = %v", err)
	}
}

// TestRootCmdPolicyLogSkippedOnAsk confirms an "ask" decision (not a hard
// block) never creates the policy log file — only "deny" counts as blocked.
func TestRootCmdPolicyLogSkippedOnAsk(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: ask
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	policyLogPath := filepath.Join(t.TempDir(), "policy.log")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath, "--policy-log-file", policyLogPath})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, err := os.Stat(policyLogPath); !os.IsNotExist(err) {
		t.Fatalf("expected no policy log file for an ask decision, stat err = %v", err)
	}
}

// TestRootCmdPolicyLogDisabled confirms an empty --policy-log-file disables
// the policy log entirely, even when a call is denied.
func TestRootCmdPolicyLogDisabled(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: deny
    reason: "blocked by test policy"
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath, "--policy-log-file", ""})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a deny decision", stdout.String())
	}
}

// TestRootCmdPolicyLogDefaultFilename confirms the policy log is on by
// default: with no --policy-log-file override, a denied call writes
// ".hookmon-policy.log" in the current directory.
func TestRootCmdPolicyLogDefaultFilename(t *testing.T) {
	t.Chdir(t.TempDir())

	policyYAML := `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    action: deny
    reason: "blocked by test policy"
`
	if err := os.WriteFile(".hookmon-policy.yaml", []byte(policyYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode"})
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a deny decision", stdout.String())
	}

	b, err := os.ReadFile(".hookmon-policy.log")
	if err != nil {
		t.Fatalf("reading default policy log file: %v", err)
	}
	if !bytes.Contains(b, []byte(`"action": "deny"`)) {
		t.Fatalf("policy log missing deny record:\n%s", b)
	}
}
