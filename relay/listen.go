package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// syncWriter serializes concurrent writes to an underlying io.Writer.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// Listen accepts TCP connections on cfg.Addr and prints each envelope to out.
func Listen(ctx context.Context, cfg Config, out io.Writer) error {
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Addr, err)
	}
	defer ln.Close()

	out = &syncWriter{w: out}

	fmt.Fprintf(out, "hookmon: listening on %s\n", ln.Addr().String())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go handleConn(conn, out)
	}
}

func handleConn(conn net.Conn, out io.Writer) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	body, err := io.ReadAll(conn)
	if err != nil {
		fmt.Fprintf(out, "hookmon: read error: %v\n", err)
		return
	}
	if len(body) == 0 {
		return
	}

	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		fmt.Fprintf(out, "%s\n", body)
		return
	}

	pretty, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(out, "%s\n", body)
		return
	}
	fmt.Fprintf(out, "%s\n", pretty)
}
