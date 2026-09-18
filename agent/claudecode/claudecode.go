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

// permissionDecisionOutput is the PreToolUse hookSpecificOutput shape Claude
// Code uses to allow/deny/ask a tool call. Other events use a different,
// unresearched "decision" schema and are not supported here yet — see
// eventSpec.PermissionDecision.
type permissionDecisionOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
}

func (Provider) Acknowledge(stdout io.Writer, event string, decision agent.Decision) error {
	if decision.Action == agent.Allow && decision.Reason == "" {
		_, err := io.WriteString(stdout, "{}\n")
		return err
	}

	var spec eventSpec
	for _, e := range events {
		if e.Name == event {
			spec = e
			break
		}
	}
	if !spec.PermissionDecision {
		_, err := io.WriteString(stdout, "{}\n")
		return err
	}

	var out permissionDecisionOutput
	out.HookSpecificOutput.HookEventName = event
	out.HookSpecificOutput.PermissionDecision = decision.Action.String()
	out.HookSpecificOutput.PermissionDecisionReason = decision.Reason

	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(b, '\n'))
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
// "matcher" for it (tool name, trigger type, etc.), and whether it accepts a
// hookSpecificOutput.permissionDecision response.
//
// PermissionDecision is set only for PreToolUse: it's the only event with a
// confirmed permissionDecision schema. Other events that can influence
// control flow (PostToolUse, Stop, ...) use a different, unresearched
// top-level "decision" field and are a deliberate scope cut for now, not an
// oversight.
type eventSpec struct {
	Name               string
	Matcher            bool
	PermissionDecision bool
}

// All Claude Code hook events from the "Hook lifecycle" table at
// https://code.claude.com/docs/en/hooks
var events = []eventSpec{
	{Name: "SessionStart", Matcher: true},
	{Name: "Setup", Matcher: true},
	{Name: "UserPromptSubmit", Matcher: false},
	{Name: "UserPromptExpansion", Matcher: true},
	{Name: "PreToolUse", Matcher: true, PermissionDecision: true},
	{Name: "PermissionRequest", Matcher: true},
	{Name: "PermissionDenied", Matcher: true},
	{Name: "PostToolUse", Matcher: true},
	{Name: "PostToolUseFailure", Matcher: true},
	{Name: "PostToolBatch", Matcher: false},
	{Name: "Notification", Matcher: true},
	{Name: "MessageDisplay", Matcher: false},
	{Name: "SubagentStart", Matcher: true},
	{Name: "SubagentStop", Matcher: true},
	{Name: "TaskCreated", Matcher: false},
	{Name: "TaskCompleted", Matcher: false},
	{Name: "Stop", Matcher: false},
	{Name: "StopFailure", Matcher: true},
	{Name: "TeammateIdle", Matcher: false},
	{Name: "InstructionsLoaded", Matcher: true},
	{Name: "ConfigChange", Matcher: true},
	{Name: "CwdChanged", Matcher: false},
	{Name: "DirectoryAdded", Matcher: true},
	{Name: "FileChanged", Matcher: true},
	{Name: "WorktreeCreate", Matcher: false},
	{Name: "WorktreeRemove", Matcher: false},
	{Name: "PreCompact", Matcher: true},
	{Name: "PostCompact", Matcher: true},
	{Name: "PreModelSwitch", Matcher: true},
	{Name: "PostModelSwitch", Matcher: true},
	{Name: "Elicitation", Matcher: true},
	{Name: "ElicitationResult", Matcher: true},
	{Name: "SessionEnd", Matcher: true},
}
