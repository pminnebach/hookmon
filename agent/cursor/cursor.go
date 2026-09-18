package cursor

import (
	"encoding/json"
	"io"

	"hookmon/agent"
)

func init() {
	agent.Register(Provider{})
}

// Provider integrates Cursor agent hooks.
type Provider struct{}

func (Provider) Name() string { return "cursor" }

func (Provider) Events() []string {
	names := make([]string, len(events))
	for i, e := range events {
		names[i] = e.Name
	}
	return names
}

// permissionOutput is the flat shape Cursor uses to allow/deny/ask a hook's
// underlying action.
type permissionOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
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

	out := permissionOutput{
		Permission:   decision.Action.String(),
		UserMessage:  decision.Reason,
		AgentMessage: decision.Reason,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	_, err = stdout.Write(append(b, '\n'))
	return err
}

func (Provider) HooksConfig(sendCmd string) ([]byte, error) {
	hooks := make(map[string][]map[string]string, len(events))
	for _, e := range events {
		hooks[e.Name] = []map[string]string{{"command": sendCmd}}
	}
	return json.MarshalIndent(map[string]any{
		"version": 1,
		"hooks":   hooks,
	}, "", "  ")
}

// eventSpec is a hook event name plus whether Cursor accepts a
// {"permission": ...} response for it. Confirmed against
// https://cursor.com/docs/agent/hooks.
type eventSpec struct {
	Name               string
	PermissionDecision bool
}

// All Cursor hook events from https://cursor.com/docs/hooks
var events = []eventSpec{
	{Name: "sessionStart"},
	{Name: "sessionEnd"},
	{Name: "preToolUse", PermissionDecision: true},
	{Name: "postToolUse", PermissionDecision: true},
	{Name: "postToolUseFailure", PermissionDecision: true},
	{Name: "subagentStart", PermissionDecision: true},
	{Name: "subagentStop"},
	{Name: "beforeShellExecution", PermissionDecision: true},
	{Name: "afterShellExecution"},
	{Name: "beforeMCPExecution", PermissionDecision: true},
	{Name: "afterMCPExecution"},
	{Name: "beforeReadFile", PermissionDecision: true},
	{Name: "afterFileEdit"},
	{Name: "beforeSubmitPrompt"},
	{Name: "preCompact"},
	{Name: "stop"},
	{Name: "afterAgentResponse"},
	{Name: "afterAgentThought"},
	{Name: "beforeTabFileRead", PermissionDecision: true},
	{Name: "afterTabFileEdit"},
	{Name: "workspaceOpen"},
}
