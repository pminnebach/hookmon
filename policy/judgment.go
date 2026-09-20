package policy

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"hookmon/judge"
)

// confidenceSuffix turns a When key into a reference to a choice or score
// answer's confidence rather than its value, e.g. "intent.confidence".
const confidenceSuffix = ".confidence"

// hit records the judgment answer that satisfied a rule, for the policy log.
type hit struct {
	ID        string
	Value     float64
	Condition string
}

// Questions returns the union of judgment definitions referenced by the When
// clauses of rules, resolved against cfg.Judgments. missing lists referenced
// IDs with no declaration; they are not asked, so any rule depending on one
// takes its OnError action.
//
// The result is empty when no rule carries a When clause, which is what lets
// the caller skip the network entirely.
func Questions(cfg Config, rules []Rule) (qs map[string]judge.Question, missing []string) {
	seen := map[string]bool{}
	for _, r := range rules {
		for key := range r.When {
			id := strings.TrimSuffix(key, confidenceSuffix)
			if seen[id] {
				continue
			}
			seen[id] = true
			q, ok := cfg.Judgments[id]
			if !ok {
				missing = append(missing, id)
				continue
			}
			if qs == nil {
				qs = map[string]judge.Question{}
			}
			qs[id] = q
		}
	}
	sort.Strings(missing)
	return qs, missing
}

var errNoAnswer = errors.New("no answer")

// evalWhen reports whether every condition in w is satisfied by answers.
//
// A non-nil error means the clause could not be evaluated at all — an answer
// was missing, mistyped, or the condition was malformed — and the caller
// falls back to the rule's OnError action. That is deliberately distinct
// from a clean "evaluated, and it did not match".
func evalWhen(w map[string]string, answers judge.Answers) (bool, hit, error) {
	// Sorted so a multi-condition clause reports a stable judgment in the
	// policy log rather than whichever key Go's map iteration produced.
	keys := make([]string, 0, len(w))
	for k := range w {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var first hit
	for _, key := range keys {
		ok, value, err := evalOne(key, w[key], answers)
		if err != nil {
			return false, hit{}, fmt.Errorf("%s: %w", key, err)
		}
		if !ok {
			return false, hit{}, nil
		}
		if first.ID == "" {
			first = hit{ID: key, Value: value, Condition: w[key]}
		}
	}
	return true, first, nil
}

func evalOne(key, expr string, answers judge.Answers) (bool, float64, error) {
	id := strings.TrimSuffix(key, confidenceSuffix)
	wantConfidence := id != key

	a, ok := answers[id]
	if !ok {
		return false, 0, errNoAnswer
	}

	cond, err := parseCondition(expr)
	if err != nil {
		return false, 0, err
	}

	// Pick the operand this key refers to.
	var (
		num    float64
		text   string
		isText bool
	)
	switch {
	case wantConfidence:
		if a.Type == judge.TypeNoul {
			// A noul's probability is the whole signal; the API returns no
			// separate confidence, so this is a policy-file mistake.
			return false, 0, errors.New("noul answers have no confidence")
		}
		num = a.Confidence
	case a.Type == judge.TypeNoul:
		num = a.Noul
	case a.Type == judge.TypeScore:
		num = a.Score
	case a.Type == judge.TypeChoice:
		text, isText = a.Choice, true
	default:
		return false, 0, fmt.Errorf("unknown answer type %q", a.Type)
	}

	if isText != !cond.isNum {
		return false, 0, fmt.Errorf("condition %q does not fit a %s answer", expr, a.Type)
	}
	if isText {
		return cond.compareText(text), 0, nil
	}
	return cond.compareNum(num), num, nil
}

// condition is a parsed threshold expression such as ">= 0.85" or
// "== exfiltrate".
type condition struct {
	op    string
	num   float64
	text  string
	isNum bool
}

// operators are checked longest-first so ">=" is not read as ">".
var operators = []string{">=", "<=", "==", "!=", ">", "<"}

// parseCondition parses a threshold expression.
//
// A bare value is accepted and is the common case in hand-written YAML: a
// bare number means ">=", a bare word means "==". Rejecting them would turn
// a plausible typo into a rule that silently never fires, which is the worst
// outcome in a matcher that decides whether to block.
func parseCondition(s string) (condition, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return condition{}, errors.New("empty condition")
	}

	op := ""
	for _, candidate := range operators {
		if strings.HasPrefix(s, candidate) {
			op, s = candidate, strings.TrimSpace(s[len(candidate):])
			break
		}
	}
	if s == "" {
		return condition{}, fmt.Errorf("condition %q has an operator but no value", op)
	}

	if n, err := strconv.ParseFloat(s, 64); err == nil {
		if op == "" {
			op = ">="
		}
		return condition{op: op, num: n, isNum: true}, nil
	}
	if op == "" {
		op = "=="
	}
	if op != "==" && op != "!=" {
		return condition{}, fmt.Errorf("operator %q needs a number, got %q", op, s)
	}
	return condition{op: op, text: s}, nil
}

func (c condition) compareNum(v float64) bool {
	switch c.op {
	case ">=":
		return v >= c.num
	case ">":
		return v > c.num
	case "<=":
		return v <= c.num
	case "<":
		return v < c.num
	case "==":
		return v == c.num
	case "!=":
		return v != c.num
	}
	return false
}

func (c condition) compareText(v string) bool {
	if c.op == "!=" {
		return v != c.text
	}
	return v == c.text
}

// Validate reports every structural problem in cfg: unknown judgment types,
// When clauses referencing an undeclared judgment, unparseable conditions,
// and confidence references on a noul.
//
// It never rejects a config — hookmon warns and carries on, consistent with
// its fail-open contract. Because the policy file is re-read on every
// invocation, a typo surfaces on the very next hook event.
func (cfg Config) Validate() []error {
	var errs []error

	ids := make([]string, 0, len(cfg.Judgments))
	for id := range cfg.Judgments {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		switch cfg.Judgments[id].Type {
		case judge.TypeNoul, judge.TypeChoice, judge.TypeScore:
		default:
			errs = append(errs, fmt.Errorf("judgment %q: unknown type %q", id, cfg.Judgments[id].Type))
		}
	}

	for i, r := range cfg.Rules {
		keys := make([]string, 0, len(r.When))
		for k := range r.When {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, key := range keys {
			id := strings.TrimSuffix(key, confidenceSuffix)
			q, ok := cfg.Judgments[id]
			if !ok {
				errs = append(errs, fmt.Errorf("rule %d: when: references undeclared judgment %q", i, id))
				continue
			}
			if id != key && q.Type == judge.TypeNoul {
				errs = append(errs, fmt.Errorf("rule %d: %q: noul answers have no confidence", i, key))
			}
			cond, err := parseCondition(r.When[key])
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %d: %q: %w", i, key, err))
				continue
			}
			// The judgment's type is declared, so a condition that could
			// never fit it is knowable now rather than at the next hook.
			wantsNum := id != key || q.Type != judge.TypeChoice
			if wantsNum != cond.isNum {
				errs = append(errs, fmt.Errorf(
					"rule %d: %q: condition %q does not fit a %s judgment", i, key, r.When[key], q.Type))
			}
		}

		switch r.OnError {
		case "", "allow", "ask", "deny":
		default:
			errs = append(errs, fmt.Errorf("rule %d: unknown on-error %q", i, r.OnError))
		}
	}
	return errs
}
