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

func (Provider) Events() []string { return events }

func (Provider) Acknowledge(stdout io.Writer) error {
	_, err := io.WriteString(stdout, "{}\n")
	return err
}

func (Provider) HooksConfig(sendCmd string) ([]byte, error) {
	hooks := make(map[string][]map[string]string, len(events))
	for _, e := range events {
		hooks[e] = []map[string]string{{"command": sendCmd}}
	}
	return json.MarshalIndent(map[string]any{
		"version": 1,
		"hooks":   hooks,
	}, "", "  ")
}

// All Cursor hook events from https://cursor.com/docs/hooks
var events = []string{
	"sessionStart",
	"sessionEnd",
	"preToolUse",
	"postToolUse",
	"postToolUseFailure",
	"subagentStart",
	"subagentStop",
	"beforeShellExecution",
	"afterShellExecution",
	"beforeMCPExecution",
	"afterMCPExecution",
	"beforeReadFile",
	"afterFileEdit",
	"beforeSubmitPrompt",
	"preCompact",
	"stop",
	"afterAgentResponse",
	"afterAgentThought",
	"beforeTabFileRead",
	"afterTabFileEdit",
	"workspaceOpen",
}
