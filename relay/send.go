package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const dialTimeout = 2 * time.Second

// Send reads a raw agent hook payload, wraps it in an Envelope, and posts it
// to the listener at cfg.Addr. Failures are written to errOut; the caller
// should still acknowledge the host agent (fail-open).
func Send(ctx context.Context, cfg Config, payload []byte, errOut io.Writer) error {
	if !json.Valid(payload) {
		fmt.Fprintf(errOut, "hookmon: payload is not valid JSON\n")
		return fmt.Errorf("payload is not valid JSON")
	}

	env := Envelope{
		Agent:   cfg.Agent,
		Payload: json.RawMessage(payload),
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", cfg.Addr)
	if err != nil {
		fmt.Fprintf(errOut, "hookmon: dial %s: %v\n", cfg.Addr, err)
		return fmt.Errorf("dial %s: %w", cfg.Addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	}

	if _, err := conn.Write(body); err != nil {
		fmt.Fprintf(errOut, "hookmon: write: %v\n", err)
		return fmt.Errorf("write: %w", err)
	}
	return nil
}
