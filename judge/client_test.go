package judge_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"hookmon/judge"
)

func testRequest() judge.Request {
	return judge.Request{
		Model: "jev-latest",
		State: judge.BuildState(judge.Input{
			Agent: "claudecode", Event: "PreToolUse", Tool: "Bash",
			ToolInput: `{"command":"rm -r -f ./src"}`,
		}, false),
		Questions: map[string]judge.Question{
			"destroys_work": {
				Type:         judge.TypeNoul,
				Instructions: "would this destroy work?",
				Criteria:     map[string]any{"true": "yes it would", "false": "no it would not"},
			},
		},
	}
}

func TestAskSendsExpectedRequest(t *testing.T) {
	var gotAuth, gotType, gotMethod string
	var body map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotType, gotMethod = r.Header.Get("Authorization"), r.Header.Get("Content-Type"), r.Method
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		io.WriteString(w, `{"answers":{"destroys_work":{"type":"noul","noul":0.9}}}`)
	}))
	defer srv.Close()

	c := &judge.HTTPClient{APIKey: "test-key", Endpoint: srv.URL}
	if _, err := c.Ask(context.Background(), testRequest()); err != nil {
		t.Fatalf("Ask: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s", gotMethod)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("authorization = %q", gotAuth)
	}
	if gotType != "application/json" {
		t.Fatalf("content-type = %q", gotType)
	}
	if body["model"] != "jev-latest" {
		t.Fatalf("model = %v", body["model"])
	}

	qs, ok := body["questions"].(map[string]any)
	if !ok {
		t.Fatalf("questions = %v", body["questions"])
	}
	q, ok := qs["destroys_work"].(map[string]any)
	if !ok {
		t.Fatalf("question missing: %v", qs)
	}
	if q["type"] != judge.TypeNoul || q["instructions"] != "would this destroy work?" {
		t.Fatalf("question = %v", q)
	}

	state, ok := body["state"].(map[string]any)
	if !ok {
		t.Fatalf("state = %v", body["state"])
	}
	ti, ok := state["tool_input"].(map[string]any)
	if !ok {
		t.Fatalf("tool_input = %v", state["tool_input"])
	}
	if ti["command"] != "rm -r -f ./src" {
		t.Fatalf("command = %v", ti["command"])
	}
}

func TestAskParsesEveryAnswerType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"model":"jev-latest","answers":{
			"a":{"type":"noul","noul":0.92},
			"b":{"type":"choice","choice":"shared","confidence":0.78,"probabilities":{"shared":0.78}},
			"c":{"type":"score","score":1.6,"confidence":0.81}
		}}`)
	}))
	defer srv.Close()

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	got, err := c.Ask(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}

	if got["a"].Noul != 0.92 {
		t.Fatalf("noul = %v", got["a"].Noul)
	}
	// A noul carries no confidence; it must stay zero rather than pick up a
	// value from somewhere else.
	if got["a"].Confidence != 0 {
		t.Fatalf("noul confidence = %v, want 0", got["a"].Confidence)
	}
	if got["b"].Choice != "shared" || got["b"].Confidence != 0.78 {
		t.Fatalf("choice = %+v", got["b"])
	}
	if got["c"].Score != 1.6 || got["c"].Confidence != 0.81 {
		t.Fatalf("score = %+v", got["c"])
	}
}

func TestAskWithoutAPIKeyDoesNotCallOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Ask called out with no API key")
	}))
	defer srv.Close()

	c := &judge.HTTPClient{Endpoint: srv.URL}
	if _, err := c.Ask(context.Background(), testRequest()); !errors.Is(err, judge.ErrNoAPIKey) {
		t.Fatalf("err = %v, want ErrNoAPIKey", err)
	}
}

func TestAskWithNoQuestionsDoesNotCallOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Ask called out with no questions")
	}))
	defer srv.Close()

	req := testRequest()
	req.Questions = nil

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	got, err := c.Ask(context.Background(), req)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestAskStatusErrors(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, judge.ErrUnauthorized},
		{http.StatusForbidden, judge.ErrUnauthorized},
		{http.StatusUnprocessableEntity, judge.ErrBadRequest},
		{http.StatusTooManyRequests, judge.ErrRateLimited},
		{529, judge.ErrOverloaded},
	}
	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			io.WriteString(w, `{"error":"nope"}`)
		}))

		client := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
		_, err := client.Ask(context.Background(), testRequest())
		if !errors.Is(err, c.want) {
			t.Errorf("status %d: err = %v, want %v", c.status, err, c.want)
		}
		srv.Close()
	}
}

// A 422 is the one error a human can fix, so the body has to survive.
func TestAsk422IncludesResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(w, `{"detail":"criteria must be an array for score"}`)
	}))
	defer srv.Close()

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	_, err := c.Ask(context.Background(), testRequest())
	if err == nil || !strings.Contains(err.Error(), "criteria must be an array") {
		t.Fatalf("err = %v, want it to carry the body", err)
	}
}

func TestAskUnexpectedStatusErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	if _, err := c.Ask(context.Background(), testRequest()); err == nil {
		t.Fatal("want an error for a 500")
	}
}

func TestAskMalformedResponseErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"answers":`)
	}))
	defer srv.Close()

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	if _, err := c.Ask(context.Background(), testRequest()); err == nil {
		t.Fatal("want an error for a truncated body")
	}
}

func TestAskAnswerlessResponseErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"model":"jev-latest"}`)
	}))
	defer srv.Close()

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	if _, err := c.Ask(context.Background(), testRequest()); err == nil {
		t.Fatal("want an error when no answers came back")
	}
}

// The hook blocks the agent's tool call, so a stalled server must surface as
// a deadline rather than hanging.
func TestAskRespectsContextDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := &judge.HTTPClient{APIKey: "k", Endpoint: srv.URL}
	if _, err := c.Ask(ctx, testRequest()); err == nil {
		t.Fatal("want an error from a cancelled context")
	}
}

// Errors get printed to a shared terminal, so the key must never ride along.
func TestAskErrorDoesNotLeakAPIKey(t *testing.T) {
	c := &judge.HTTPClient{APIKey: "super-secret-key", Endpoint: "http://127.0.0.1:1"}
	_, err := c.Ask(context.Background(), testRequest())
	if err == nil {
		t.Fatal("want a connection error")
	}
	if strings.Contains(err.Error(), "super-secret-key") {
		t.Fatalf("API key leaked into error: %v", err)
	}
}
