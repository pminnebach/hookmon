package judge_test

import (
	"encoding/json"
	"strings"
	"testing"

	"hookmon/judge"
)

func TestBuildStateCopiesEventFields(t *testing.T) {
	st := judge.BuildState(judge.Input{
		Agent: "claudecode", Event: "PreToolUse", Tool: "Bash", Cwd: "/workspace",
		ToolInput: `{"command":"ls"}`,
	}, false)

	if st.Agent != "claudecode" || st.Event != "PreToolUse" || st.Tool != "Bash" || st.Cwd != "/workspace" {
		t.Fatalf("state = %+v", st)
	}
}

// The whole point of sending raw tool_input is that fields hookmon has never
// heard of still reach the model — WebFetch's url, an MCP tool's arguments.
func TestBuildStateKeepsUnknownToolInputFields(t *testing.T) {
	st := judge.BuildState(judge.Input{
		Tool:      "WebFetch",
		ToolInput: `{"url":"https://example.com/x","prompt":"summarize"}`,
	}, false)

	var got map[string]any
	if err := json.Unmarshal(st.ToolInput, &got); err != nil {
		t.Fatalf("tool_input is not valid JSON: %v", err)
	}
	if got["url"] != "https://example.com/x" {
		t.Fatalf("url = %v, want it preserved", got["url"])
	}
	if got["prompt"] != "summarize" {
		t.Fatalf("prompt = %v", got["prompt"])
	}
}

// hookmon's purpose is keeping secrets off the wire, so it must not ship a
// file's contents to a third party in order to judge the write.
func TestBuildStateDropsContentFields(t *testing.T) {
	st := judge.BuildState(judge.Input{
		Tool:      "Write",
		ToolInput: `{"file_path":"/x/.env","content":"AWS_SECRET_ACCESS_KEY=hunter2"}`,
	}, false)

	if strings.Contains(string(st.ToolInput), "hunter2") {
		t.Fatalf("secret leaked into state: %s", st.ToolInput)
	}
	var got map[string]any
	if err := json.Unmarshal(st.ToolInput, &got); err != nil {
		t.Fatal(err)
	}
	if got["file_path"] != "/x/.env" {
		t.Fatalf("file_path = %v, want it kept (the judgment needs it)", got["file_path"])
	}
	if _, ok := got["content"]; ok {
		t.Fatalf("content survived redaction: %v", got)
	}
}

func TestBuildStateDropsEditStrings(t *testing.T) {
	st := judge.BuildState(judge.Input{
		Tool:      "Edit",
		ToolInput: `{"file_path":"a.go","old_string":"secret-a","new_string":"secret-b"}`,
	}, false)

	if strings.Contains(string(st.ToolInput), "secret-") {
		t.Fatalf("edit content leaked: %s", st.ToolInput)
	}
}

func TestBuildStateSendContentOptIn(t *testing.T) {
	in := judge.Input{Tool: "Write", ToolInput: `{"content":"hunter2"}`}

	if st := judge.BuildState(in, true); !strings.Contains(string(st.ToolInput), "hunter2") {
		t.Fatalf("opt-in did not pass content through: %s", st.ToolInput)
	}
}

func TestBuildStateTruncatesLongStrings(t *testing.T) {
	long := strings.Repeat("x", 5000)
	st := judge.BuildState(judge.Input{
		Tool:      "Bash",
		ToolInput: `{"command":"` + long + `"}`,
	}, false)

	if len(st.ToolInput) > 4096 {
		t.Fatalf("state = %d bytes, want it capped", len(st.ToolInput))
	}
	var got map[string]any
	if err := json.Unmarshal(st.ToolInput, &got); err != nil {
		t.Fatalf("truncation produced invalid JSON: %v", err)
	}
}

// Truncation must not split a rune, or the result stops being valid JSON.
func TestBuildStateTruncationStaysValidUTF8(t *testing.T) {
	st := judge.BuildState(judge.Input{
		ToolInput: `{"command":"` + strings.Repeat("é", 1000) + `"}`,
	}, false)

	var got map[string]any
	if err := json.Unmarshal(st.ToolInput, &got); err != nil {
		t.Fatalf("invalid JSON after truncation: %v", err)
	}
	if strings.Contains(got["command"].(string), "�") {
		t.Fatalf("truncation split a rune")
	}
}

func TestBuildStateEmptyToolInput(t *testing.T) {
	st := judge.BuildState(judge.Input{Agent: "cursor", Event: "preToolUse"}, false)
	if st.ToolInput != nil {
		t.Fatalf("tool_input = %s, want none", st.ToolInput)
	}
}

// A malformed payload must not produce half a state; it produces none, so
// the judgment has no evidence and the rule fails open.
func TestBuildStateMalformedToolInputYieldsNone(t *testing.T) {
	st := judge.BuildState(judge.Input{ToolInput: "not-json"}, false)
	if st.ToolInput != nil {
		t.Fatalf("tool_input = %s, want none", st.ToolInput)
	}
}

func TestStateMarshalsWithoutEmptyFields(t *testing.T) {
	b, err := json.Marshal(judge.BuildState(judge.Input{Agent: "cursor"}, false))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "tool_input") || strings.Contains(string(b), "cwd") {
		t.Fatalf("state = %s, want empty fields omitted", b)
	}
}
