package claudecode

import (
	"encoding/json"
	"io"

	"hookmon/agent"
)

func init() {
	agent.Register(Provider{})
}

// Provider integrates Claude Code hooks.
type Provider struct{}

func (Provider) Name() string { return "claudecode" }

func (Provider) Events() []string {
	names := make([]string, len(events))
	for i, e := range events {
		names[i] = e.Name
	}
	return names
}

func (Provider) Acknowledge(stdout io.Writer) error {
	_, err := io.WriteString(stdout, "{}\n")
	return err
}

// hookCmd is a single "hooks" array entry under a matcher group.
type hookCmd struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// hookGroup is one entry in the per-event array; Matcher is omitted for
// events that don't support one.
type hookGroup struct {
	Matcher string    `json:"matcher,omitempty"`
	Hooks   []hookCmd `json:"hooks"`
}

func (Provider) HooksConfig(sendCmd string) ([]byte, error) {
	hooks := make(map[string][]hookGroup, len(events))
	for _, e := range events {
		group := hookGroup{Hooks: []hookCmd{{Type: "command", Command: sendCmd}}}
		if e.Matcher {
			group.Matcher = "*"
		}
		hooks[e.Name] = []hookGroup{group}
	}
	return json.MarshalIndent(map[string]any{"hooks": hooks}, "", "  ")
}

// eventSpec is a hook event name plus whether Claude Code supports a
// "matcher" for it (tool name, trigger type, etc.).
type eventSpec struct {
	Name    string
	Matcher bool
}

// All Claude Code hook events from the "Hook lifecycle" table at
// https://code.claude.com/docs/en/hooks
var events = []eventSpec{
	{"SessionStart", true},
	{"Setup", true},
	{"UserPromptSubmit", false},
	{"UserPromptExpansion", true},
	{"PreToolUse", true},
	{"PermissionRequest", true},
	{"PermissionDenied", true},
	{"PostToolUse", true},
	{"PostToolUseFailure", true},
	{"PostToolBatch", false},
	{"Notification", true},
	{"MessageDisplay", false},
	{"SubagentStart", true},
	{"SubagentStop", true},
	{"TaskCreated", false},
	{"TaskCompleted", false},
	{"Stop", false},
	{"StopFailure", true},
	{"TeammateIdle", false},
	{"InstructionsLoaded", true},
	{"ConfigChange", true},
	{"CwdChanged", false},
	{"DirectoryAdded", true},
	{"FileChanged", true},
	{"WorktreeCreate", false},
	{"WorktreeRemove", false},
	{"PreCompact", true},
	{"PostCompact", true},
	{"PreModelSwitch", true},
	{"PostModelSwitch", true},
	{"Elicitation", true},
	{"ElicitationResult", true},
	{"SessionEnd", true},
}
