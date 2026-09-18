package agent

import (
	"fmt"
	"io"
	"sync"
)

// Action is the outcome of a policy decision for a tool call.
//
// The zero value is Allow, so a zero-value Decision fails open. Values are
// ordered by precedence (Deny > Ask > Allow) so callers resolving multiple
// matching rules can pick the strictest one with a plain ">" comparison.
type Action int

const (
	Allow Action = iota
	Ask
	Deny
)

func (a Action) String() string {
	switch a {
	case Deny:
		return "deny"
	case Ask:
		return "ask"
	default:
		return "allow"
	}
}

// Decision is a policy verdict for a hook event, passed to Provider.
// Acknowledge so it can be encoded in whatever shape that agent's hook
// protocol expects.
type Decision struct {
	Action Action
	Reason string
}

// Provider is a pluggable coding-agent hook integration.
type Provider interface {
	Name() string
	Events() []string
	// Acknowledge writes the hook response for event, encoding decision in
	// the agent-specific shape. Providers that don't support a decision for
	// event, or an Allow decision with no reason, should emit their
	// unconditional-allow acknowledgment (e.g. "{}\n").
	Acknowledge(stdout io.Writer, event string, decision Decision) error
	HooksConfig(sendCmd string) ([]byte, error)
}

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider. Panics on duplicate names.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	name := p.Name()
	if _, ok := providers[name]; ok {
		panic("agent: duplicate provider " + name)
	}
	providers[name] = p
}

// Lookup returns a registered provider by name.
func Lookup(name string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[name]
	if !ok {
		return nil, fmt.Errorf("unknown agent %q (registered: %v)", name, namesLocked())
	}
	return p, nil
}

// Names returns registered provider names.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	return namesLocked()
}

func namesLocked() []string {
	out := make([]string, 0, len(providers))
	for name := range providers {
		out = append(out, name)
	}
	return out
}
