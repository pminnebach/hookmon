package cmd_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"hookmon/cmd"
	"hookmon/relay"
)

var listeningRE = regexp.MustCompile(`hookmon: listening on (\S+)`)

// TestListenCmdLogFile exercises the actual `listen --log-file` CLI wiring
// (flag parsing -> Viper decode -> os.OpenFile in cmd/listen.go), not just
// the lower-level relay.Listen function.
func TestListenCmdLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hookmon.log")

	root := cmd.NewRootCmd()
	root.SetArgs([]string{"listen", "--addr", "127.0.0.1:0", "--log-file", path})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- root.ExecuteContext(ctx)
	}()

	addr := waitForAddr(t, path)

	payload := []byte(`{"hook_event_name":"sessionStart"}`)
	if err := relay.Send(t.Context(), relay.Config{Addr: addr, Agent: "cursor"}, payload, os.Stderr); err != nil {
		t.Fatalf("Send: %v", err)
	}

	waitForFileContent(t, path, `"agent": "cursor"`, `"hook_event_name": "sessionStart"`)

	cancel()
	if err := <-done; err != nil && ctx.Err() == nil {
		t.Fatalf("listen: %v", err)
	}
}

func waitForAddr(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			if m := listeningRE.FindSubmatch(b); m != nil {
				return string(m[1])
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for listen address in %s", path)
	return ""
}

func waitForFileContent(t *testing.T, path string, want ...string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			ok := true
			for _, w := range want {
				if !bytes.Contains(b, []byte(w)) {
					ok = false
					break
				}
			}
			if ok {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	b, _ := os.ReadFile(path)
	t.Fatalf("log file missing %v:\n%s", want, b)
}
