package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Defaults for the TypeSafe System One API.
const (
	DefaultEndpoint = "https://api.typesafe.ai/v1/systemone"
	DefaultModel    = "jev-latest"
	DefaultTimeout  = 1500 * time.Millisecond
)

// Errors callers may want to distinguish when writing the stderr warning.
var (
	ErrNoAPIKey     = errors.New("no TypeSafe API key (set HOOKMON_TYPESAFE_API_KEY)")
	ErrUnauthorized = errors.New("unauthorized (check HOOKMON_TYPESAFE_API_KEY)")
	ErrBadRequest   = errors.New("request rejected (check the judgments: block)")
	ErrRateLimited  = errors.New("rate limited")
	ErrOverloaded   = errors.New("service overloaded")
)

// Request is one System One call. Every question in it is evaluated in
// parallel server-side, so asking a battery of five costs about what asking
// one costs — which is why hookmon collects the union of judgments up front
// and sends exactly one request per hook event.
type Request struct {
	Model     string              `json:"model"`
	State     State               `json:"state"`
	Questions map[string]Question `json:"questions"`
}

// Client evaluates a battery of questions about one state.
//
// It is the single injection seam: cmd supplies *HTTPClient, optionally
// wrapped in *Cache, and tests supply a fake. A nil Client means "never
// ask", which is how a machine with no API key behaves.
type Client interface {
	Ask(ctx context.Context, req Request) (Answers, error)
}

// HTTPClient calls the TypeSafe System One API. The zero value works except
// for APIKey; Endpoint, Model and HTTP fall back to defaults.
type HTTPClient struct {
	APIKey   string
	Endpoint string
	HTTP     *http.Client
}

type wireResponse struct {
	Model   string  `json:"model"`
	Answers Answers `json:"answers"`
	Usage   struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// Ask posts req and returns the typed answers.
//
// There are deliberately no retries. This runs inside a PreToolUse hook that
// blocks the agent's tool call, so the timeout is the entire budget; a 429
// or 529 takes the caller's on-error path instead of spending it on backoff.
func (c *HTTPClient) Ask(ctx context.Context, req Request) (Answers, error) {
	if c.APIKey == "" {
		return nil, ErrNoAPIKey
	}
	if len(req.Questions) == 0 {
		return Answers{}, nil
	}
	if req.Model == "" {
		req.Model = DefaultModel
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encoding request: %w", err)
	}

	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	hc := c.HTTP
	if hc == nil {
		// http.DefaultClient has no timeout, so a half-open connection would
		// hang the coding agent indefinitely. Never fall back to it.
		hc = &http.Client{Timeout: DefaultTimeout}
	}

	resp, err := hc.Do(httpReq)
	if err != nil {
		// Never wrap the raw error alone: url.Error stringifies the request
		// URL, and callers print this to a shared terminal.
		return nil, fmt.Errorf("calling %s: %w", endpoint, redactKey(err, c.APIKey))
	}
	defer resp.Body.Close()

	// Cap the read: a wrong endpoint could otherwise stream forever.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		return nil, statusError(resp.StatusCode, raw)
	}

	var wire wireResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	if wire.Answers == nil {
		return nil, errors.New("response carried no answers")
	}
	return wire.Answers, nil
}

func statusError(code int, body []byte) error {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return ErrUnauthorized
	case http.StatusUnprocessableEntity:
		// The one error a human can actually fix, so include the body: a 422
		// almost always means a malformed judgment definition.
		return fmt.Errorf("%w: %s", ErrBadRequest, snippet(body))
	case http.StatusTooManyRequests:
		return ErrRateLimited
	case 529:
		return ErrOverloaded
	default:
		return fmt.Errorf("unexpected status %d: %s", code, snippet(body))
	}
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "(empty body)"
	}
	return truncate(s, 200)
}

// redactKey keeps an API key out of an error string on the off chance it
// reached a URL or a header dump.
func redactKey(err error, key string) error {
	if key == "" || !strings.Contains(err.Error(), key) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), key, "***"))
}
