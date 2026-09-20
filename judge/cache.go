package judge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache is a Client decorator that memoizes answers on disk.
//
// An in-memory cache would be useless here: every hookmon invocation is a
// fresh, short-lived process. Coding agents re-run identical commands
// constantly (go build, git status, ls), so an on-disk cache takes the API
// call, its latency, and its token cost off the majority of judged events.
//
// Every failure — unreadable directory, corrupt entry, failed write — is
// treated as a miss. The cache is an optimization and never becomes an error
// path of its own.
type Cache struct {
	Next Client
	Dir  string
	TTL  time.Duration

	// Now is injectable so expiry is testable without sleeping.
	Now func() time.Time
}

type cacheEntry struct {
	Time    time.Time `json:"time"`
	Model   string    `json:"model"`
	Answers Answers   `json:"answers"`
}

// Key derives the cache key for a request.
//
// The threshold in a rule's when: clause is deliberately not part of the
// key, because it is not part of the request: re-tuning a threshold reuses
// cached answers, while editing a judgment's instructions or criteria
// correctly misses. That makes the tuning loop both fast and correct.
//
// json.Marshal sorts map keys, so the questions blob is canonical. The raw
// tool_input passes through in whatever key order the agent emitted, which
// is byte-identical for identical tool calls — exactly the equivalence
// wanted here, so no deeper canonicalization is needed.
func Key(req Request) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n", req.Model)

	state, err := json.Marshal(req.State)
	if err != nil {
		return "", err
	}
	h.Write(state)
	h.Write([]byte{'\n'})

	qs, err := json.Marshal(req.Questions)
	if err != nil {
		return "", err
	}
	h.Write(qs)

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Cache) Ask(ctx context.Context, req Request) (Answers, error) {
	if c.Next == nil {
		return nil, ErrNoAPIKey
	}
	if c.Dir == "" || c.TTL <= 0 {
		return c.Next.Ask(ctx, req)
	}

	key, err := Key(req)
	if err != nil {
		return c.Next.Ask(ctx, req)
	}

	if answers, ok := c.get(key); ok {
		return answers, nil
	}

	answers, err := c.Next.Ask(ctx, req)
	if err != nil {
		// Never cache an error: a rate limit or an outage must not pin a
		// fail-open result in place for the whole TTL.
		return nil, err
	}
	c.put(key, req.Model, answers)
	return answers, nil
}

// path shards on the first byte of the key so a long-lived cache directory
// doesn't accumulate one enormous flat listing.
func (c *Cache) path(key string) string {
	return filepath.Join(c.Dir, key[:2], key[2:]+".json")
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cache) get(key string) (Answers, bool) {
	b, err := os.ReadFile(c.path(key))
	if err != nil {
		return nil, false
	}
	var e cacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, false
	}
	if c.now().Sub(e.Time) > c.TTL {
		return nil, false
	}
	for id, a := range e.Answers {
		a.Cached = true
		e.Answers[id] = a
	}
	return e.Answers, true
}

// put writes the entry to a temp file and renames it into place. One file
// per key plus an atomic rename is concurrency-safe across parallel hook
// processes with no locking; a single shared file would race.
func (c *Cache) put(key, model string, answers Answers) {
	p := c.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	b, err := json.Marshal(cacheEntry{Time: c.now(), Model: model, Answers: answers})
	if err != nil {
		return
	}
	// Same directory as the target, so the rename stays on one filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	if err := tmp.Close(); err != nil {
		return
	}
	_ = os.Rename(tmp.Name(), p)
}
