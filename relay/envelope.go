package relay

import "encoding/json"

// Envelope is the agent-agnostic wire format between send and listen.
type Envelope struct {
	Agent   string          `json:"agent"`
	Payload json.RawMessage `json:"payload"`
}
