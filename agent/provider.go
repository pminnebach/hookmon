package agent

import (
	"fmt"
	"io"
	"sync"
)

// Provider is a pluggable coding-agent hook integration.
type Provider interface {
	Name() string
	Events() []string
	Acknowledge(stdout io.Writer) error
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
