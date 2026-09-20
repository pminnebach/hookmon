package cmd_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hookmon/cmd"
)

// judgedPolicy denies a Bash call when destroys_work clears 0.85. It carries
// no commands: filter, which is the point: the judgment replaces the
// substring blocklist rather than narrowing it.
const judgedPolicy = `
judgments:
  destroys_work:
    type: noul
    instructions: "Would this irreversibly destroy work?"
rules:
  - event: PreToolUse
    tools: ["Bash"]
    when: {destroys_work: ">= 0.85"}
    action: deny
    reason: "This command would irreversibly destroy work."
default-action: allow
`

func writePolicy(t *testing.T, yaml string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// runHook drives the real CLI against a stub TypeSafe endpoint.
func runHook(t *testing.T, policyPath, endpoint, apiKey string, args ...string) (stdout, stderr string) {
	t.Helper()
	t.Setenv("HOOKMON_TYPESAFE_ENDPOINT", endpoint)
	t.Setenv("HOOKMON_TYPESAFE_API_KEY", apiKey)
	// Disable the cache so tests never share state through the user cache dir.
	t.Setenv("HOOKMON_TYPESAFE_CACHE_TTL", "0")

	root := cmd.NewRootCmd()
	root.SetArgs(append([]string{"--agent", "claudecode", "--policy-file", policyPath}, args...))
	root.SetIn(strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -r -f ./src"},"cwd":"/workspace"}`))

	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return out.String(), errBuf.String()
}

func stubTypeSafe(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// `rm -r -f ./src` evades the "rm -rf" substring entirely. The judgment
// catches it.
func TestRootCmdJudgmentDenies(t *testing.T) {
	srv := stubTypeSafe(t, `{"answers":{"destroys_work":{"type":"noul","noul":0.92}}}`)
	logPath := filepath.Join(t.TempDir(), "policy.log")

	stdout, _ := runHook(t, writePolicy(t, judgedPolicy), srv.URL, "test-key", "--policy-log-file", logPath)

	if !strings.Contains(stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("stdout = %q, want a deny", stdout)
	}

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reading policy log: %v", err)
	}
	for _, want := range []string{`"judgment": "destroys_work"`, `"judgment_value": 0.92`, `"judgment_condition": "\u003e= 0.85"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Fatalf("policy log missing %q:\n%s", want, b)
		}
	}
}

// The same rule must leave a harmless command alone — the false positive
// that substring matching cannot avoid.
func TestRootCmdJudgmentBelowThresholdAllows(t *testing.T) {
	srv := stubTypeSafe(t, `{"answers":{"destroys_work":{"type":"noul","noul":0.04}}}`)

	stdout, _ := runHook(t, writePolicy(t, judgedPolicy), srv.URL, "test-key")

	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want an allow", stdout)
	}
}

// The headline performance guarantee: a policy with no when: clause must
// never touch the network, so existing substring policies stay exactly as
// fast as they were.
func TestRootCmdNoWhenClauseMakesNoRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TypeSafe was called for a policy with no when: clause")
	}))
	defer srv.Close()

	policyPath := writePolicy(t, `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    commands: ["git push"]
    action: deny
`)
	stdout, _ := runHook(t, policyPath, srv.URL, "test-key")
	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want an allow", stdout)
	}
}

// A rule whose lexical filter already missed must not trigger a call
// either — that is what keeps the judged surface bounded.
func TestRootCmdNonCandidateRuleMakesNoRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TypeSafe was called for a rule that did not match lexically")
	}))
	defer srv.Close()

	policyPath := writePolicy(t, `
judgments:
  destroys_work:
    type: noul
    instructions: "Would this irreversibly destroy work?"
rules:
  - event: PreToolUse
    tools: ["Read"]
    when: {destroys_work: ">= 0.85"}
    action: deny
`)
	if stdout, _ := runHook(t, policyPath, srv.URL, "test-key"); stdout != "{}\n" {
		t.Fatalf("stdout = %q, want an allow", stdout)
	}
}

func TestRootCmdJudgmentAPIErrorFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	stdout, stderr := runHook(t, writePolicy(t, judgedPolicy), srv.URL, "test-key")

	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want fail-open allow", stdout)
	}
	if !strings.Contains(stderr, "judge") {
		t.Fatalf("stderr = %q, want a judge warning", stderr)
	}
}

func TestRootCmdMissingAPIKeyFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TypeSafe was called with no API key configured")
	}))
	defer srv.Close()

	stdout, stderr := runHook(t, writePolicy(t, judgedPolicy), srv.URL, "")

	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want fail-open allow", stdout)
	}
	if !strings.Contains(stderr, "HOOKMON_TYPESAFE_API_KEY") {
		t.Fatalf("stderr = %q, want it to name the env var", stderr)
	}
}

// on-error lets a rule that matters degrade to a prompt instead of silently
// switching itself off.
func TestRootCmdOnErrorAskDegradesToAsk(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	policyPath := writePolicy(t, `
judgments:
  destroys_work:
    type: noul
    instructions: "Would this irreversibly destroy work?"
rules:
  - event: PreToolUse
    tools: ["Bash"]
    when: {destroys_work: ">= 0.85"}
    on-error: ask
    action: deny
    reason: "Could not verify this command."
`)
	stdout, _ := runHook(t, policyPath, srv.URL, "test-key")
	if !strings.Contains(stdout, `"permissionDecision":"ask"`) {
		t.Fatalf("stdout = %q, want an ask", stdout)
	}
}

// A policy typo must be reported rather than silently producing a rule that
// never fires.
func TestRootCmdReportsUndeclaredJudgment(t *testing.T) {
	srv := stubTypeSafe(t, `{"answers":{}}`)

	policyPath := writePolicy(t, `
judgments:
  destroys_work:
    type: noul
    instructions: "Would this irreversibly destroy work?"
rules:
  - event: PreToolUse
    tools: ["Bash"]
    when: {destory_work: ">= 0.85"}
    action: deny
`)
	stdout, stderr := runHook(t, policyPath, srv.URL, "test-key")

	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want fail-open allow", stdout)
	}
	if !strings.Contains(stderr, "destory_work") {
		t.Fatalf("stderr = %q, want it to name the undeclared judgment", stderr)
	}
}

// Secrets must not be shipped to a third party in order to judge the write.
func TestRootCmdDoesNotSendFileContent(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		io.WriteString(w, `{"answers":{"exposes_secrets":{"type":"noul","noul":0.1}}}`)
	}))
	defer srv.Close()

	policyPath := writePolicy(t, `
judgments:
  exposes_secrets:
    type: noul
    instructions: "Does this expose secrets?"
rules:
  - event: PreToolUse
    when: {exposes_secrets: ">= 0.8"}
    action: deny
`)
	t.Setenv("HOOKMON_TYPESAFE_ENDPOINT", srv.URL)
	t.Setenv("HOOKMON_TYPESAFE_API_KEY", "test-key")
	t.Setenv("HOOKMON_TYPESAFE_CACHE_TTL", "0")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"--agent", "claudecode", "--policy-file", policyPath})
	root.SetIn(strings.NewReader(
		`{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/x/.env","content":"AWS_SECRET_ACCESS_KEY=hunter2"}}`))

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(io.Discard)

	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if bytes.Contains(body, []byte("hunter2")) {
		t.Fatalf("secret was sent to the API:\n%s", body)
	}
	if !bytes.Contains(body, []byte("/x/.env")) {
		t.Fatalf("file_path was not sent, so the judgment had nothing to go on:\n%s", body)
	}
}

// onErrorAskPolicy carries on-error: ask, so it distinguishes "judgments
// aren't configured" (rule inert) from "a configured judgment failed"
// (degrade to a prompt).
const onErrorAskPolicy = `
judgments:
  destroys_work:
    type: noul
    instructions: "Would this irreversibly destroy work?"
rules:
  - event: PreToolUse
    tools: ["Bash"]
    when: {destroys_work: ">= 0.85"}
    on-error: ask
    action: deny
    reason: "Could not verify this command."
default-action: allow
`

// With no API key, on-error must NOT fire: a shared policy would otherwise
// prompt on every matching call for any teammate without a key.
func TestRootCmdNoAPIKeyDoesNotTriggerOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("TypeSafe was called with no API key configured")
	}))
	defer srv.Close()

	stdout, stderr := runHook(t, writePolicy(t, onErrorAskPolicy), srv.URL, "")

	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want an allow (not an ask)", stdout)
	}
	if !strings.Contains(stderr, "HOOKMON_TYPESAFE_API_KEY") {
		t.Fatalf("stderr = %q, want it to still warn", stderr)
	}
}

// But once a key IS set, a real failure must still degrade to ask.
func TestRootCmdConfiguredFailureTriggersOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	stdout, _ := runHook(t, writePolicy(t, onErrorAskPolicy), srv.URL, "test-key")

	if !strings.Contains(stdout, `"permissionDecision":"ask"`) {
		t.Fatalf("stdout = %q, want an ask", stdout)
	}
}

// A policy field this binary doesn't know must disable the policy and warn,
// not silently reinterpret it as a different, broader rule.
func TestRootCmdUnknownPolicyFieldFailsOpen(t *testing.T) {
	policyPath := writePolicy(t, `
rules:
  - event: PreToolUse
    tools: ["Bash"]
    from_a_newer_hookmon: {x: 1}
    action: deny
    reason: "would block everything if the field were ignored"
`)
	stdout, stderr := runHook(t, policyPath, "http://127.0.0.1:1", "")

	if stdout != "{}\n" {
		t.Fatalf("stdout = %q, want fail-open allow", stdout)
	}
	if !strings.Contains(stderr, "policy") {
		t.Fatalf("stderr = %q, want a policy parse warning", stderr)
	}
}
