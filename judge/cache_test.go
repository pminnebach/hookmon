package judge_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"hookmon/judge"
)

// countingClient records how often it was asked, so tests can assert that a
// cache hit really did avoid the upstream call.
type countingClient struct {
	calls   int
	answers judge.Answers
	err     error
}

func (c *countingClient) Ask(context.Context, judge.Request) (judge.Answers, error) {
	c.calls++
	return c.answers, c.err
}

func newCache(t *testing.T, next judge.Client) *judge.Cache {
	t.Helper()
	return &judge.Cache{Next: next, Dir: t.TempDir(), TTL: time.Hour}
}

func TestCacheHitAvoidsUpstreamCall(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Type: judge.TypeNoul, Noul: 0.9}}}
	c := newCache(t, up)
	req := testRequest()

	first, err := c.Ask(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first["a"].Cached {
		t.Fatal("first answer reported as cached")
	}

	second, err := c.Ask(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if up.calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.calls)
	}
	if second["a"].Noul != 0.9 {
		t.Fatalf("cached noul = %v", second["a"].Noul)
	}
	if !second["a"].Cached {
		t.Fatal("replayed answer not marked cached")
	}
}

func TestCacheMissesOnDifferentState(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Noul: 0.9}}}
	c := newCache(t, up)

	req := testRequest()
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	req.State = judge.BuildState(judge.Input{
		Tool: "Bash", ToolInput: `{"command":"rm -rf ./build"}`,
	}, false)
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2", up.calls)
	}
}

// Editing a judgment's wording must invalidate; it is a different question.
func TestCacheMissesOnDifferentQuestions(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Noul: 0.9}}}
	c := newCache(t, up)

	req := testRequest()
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	req.Questions = map[string]judge.Question{
		"destroys_work": {Type: judge.TypeNoul, Instructions: "reworded question"},
	}
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2", up.calls)
	}
}

func TestCacheMissesOnDifferentModel(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Noul: 0.9}}}
	c := newCache(t, up)

	req := testRequest()
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Model = "jev-preview"
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2", up.calls)
	}
}

func TestCacheExpiredEntryIsAMiss(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Noul: 0.9}}}
	now := time.Now()
	c := &judge.Cache{
		Next: up, Dir: t.TempDir(), TTL: time.Hour,
		Now: func() time.Time { return now },
	}
	req := testRequest()

	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := c.Ask(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2 (entry should have expired)", up.calls)
	}
}

// An outage must not pin a fail-open result in place for the whole TTL.
func TestCacheDoesNotCacheErrors(t *testing.T) {
	up := &countingClient{err: errors.New("boom")}
	c := newCache(t, up)
	req := testRequest()

	for i := 0; i < 2; i++ {
		if _, err := c.Ask(context.Background(), req); err == nil {
			t.Fatal("want the upstream error")
		}
	}
	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2", up.calls)
	}
}

// The cache is an optimization; an unwritable directory must degrade to a
// plain pass-through, never to an error.
func TestCacheUnwritableDirStillReturnsAnswers(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Noul: 0.5}}}
	c := &judge.Cache{Next: up, Dir: "/proc/nonexistent-hookmon", TTL: time.Hour}

	got, err := c.Ask(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if got["a"].Noul != 0.5 {
		t.Fatalf("answers = %v", got)
	}
}

func TestCacheDisabledByZeroTTL(t *testing.T) {
	up := &countingClient{answers: judge.Answers{"a": {Noul: 0.9}}}
	c := &judge.Cache{Next: up, Dir: t.TempDir(), TTL: 0}
	req := testRequest()

	for i := 0; i < 2; i++ {
		if _, err := c.Ask(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	if up.calls != 2 {
		t.Fatalf("upstream calls = %d, want 2 (cache disabled)", up.calls)
	}
}

func TestKeyIsStableAcrossCalls(t *testing.T) {
	a, err := judge.Key(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	b, err := judge.Key(testRequest())
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("key not stable: %s vs %s", a, b)
	}
}
