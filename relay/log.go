package relay

import (
	"encoding/json"
	"fmt"
	"os"
)

// Log validates a raw agent hook payload, wraps it in an Envelope, and
// appends it to cfg.LogFile. If cfg.LogFile is empty, Log is a no-op.
//
// The envelope is written in a single Write call on an O_APPEND file
// descriptor, so concurrent hookmon processes appending to the same file
// cannot interleave their output.
func Log(cfg Config, payload []byte) error {
	if !json.Valid(payload) {
		return fmt.Errorf("payload is not valid JSON")
	}
	if cfg.LogFile == "" {
		return nil
	}

	env := Envelope{
		Agent:   cfg.Agent,
		Payload: json.RawMessage(payload),
	}
	pretty, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	pretty = append(pretty, '\n')

	f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", cfg.LogFile, err)
	}
	defer f.Close()

	if _, err := f.Write(pretty); err != nil {
		return fmt.Errorf("write log file %s: %w", cfg.LogFile, err)
	}
	return nil
}
