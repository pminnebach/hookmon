package relay

import (
	"encoding/json"
	"fmt"
	"os"
)

// PolicyDecision is a structured record of a single denied hook event,
// written to cfg.PolicyLogFile.
// Judgment, JudgmentValue and JudgmentCondition record the semantic answer
// that fired the rule, when one did, so thresholds can be tuned against real
// traffic rather than guessed. JudgmentValue carries no omitempty on
// purpose: a legitimate 0.0 is the most informative value there is when
// chasing a false positive, and omitempty would drop it.
//
// These are scalars rather than a slice so PolicyDecision stays comparable
// with ==, which the tests rely on.
type PolicyDecision struct {
	Time              string  `json:"time"`
	Agent             string  `json:"agent"`
	Event             string  `json:"event"`
	Tool              string  `json:"tool"`
	Path              string  `json:"path"`
	Command           string  `json:"command"`
	Action            string  `json:"action"`
	Reason            string  `json:"reason"`
	Judgment          string  `json:"judgment,omitempty"`
	JudgmentValue     float64 `json:"judgment_value"`
	JudgmentCondition string  `json:"judgment_condition,omitempty"`
}

// LogPolicyDecision appends d to cfg.PolicyLogFile. If cfg.PolicyLogFile is
// empty, LogPolicyDecision is a no-op.
//
// Like Log, the record is written in a single Write call on an O_APPEND
// file descriptor, so concurrent hookmon processes appending to the same
// file cannot interleave their output.
func LogPolicyDecision(cfg Config, d PolicyDecision) error {
	if cfg.PolicyLogFile == "" {
		return nil
	}

	pretty, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal policy decision: %w", err)
	}
	pretty = append(pretty, '\n')

	f, err := os.OpenFile(cfg.PolicyLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open policy log file %s: %w", cfg.PolicyLogFile, err)
	}
	defer f.Close()

	if _, err := f.Write(pretty); err != nil {
		return fmt.Errorf("write policy log file %s: %w", cfg.PolicyLogFile, err)
	}
	return nil
}
