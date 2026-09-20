package policy_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"hookmon/agent"
	"hookmon/judge"
	"hookmon/policy"
)

// battery is the judgment set the tests in this file resolve against.
func battery() map[string]judge.Question {
	return map[string]judge.Question{
		"destroys_work": {Type: judge.TypeNoul, Instructions: "would this destroy work?"},
		"blast_radius":  {Type: judge.TypeScore, Instructions: "how far does this reach?"},
		"destination":   {Type: judge.TypeChoice, Instructions: "where does this publish?"},
	}
}

func judgedConfig(rule policy.Rule) policy.Config {
	return policy.Config{Judgments: battery(), Rules: []policy.Rule{rule}}
}

func bashEvent() policy.Event {
	return policy.Event{Name: "PreToolUse", Tool: "Bash", Command: "rm -r -f ./src"}
}

func TestResolveWithNoulAboveThresholdDenies(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When:   map[string]string{"destroys_work": ">= 0.85"},
		Action: "deny", Reason: "destroys work",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.92},
	}}

	out := policy.ResolveWith(cfg, bashEvent(), res)
	if out.Action != agent.Deny {
		t.Fatalf("action = %v, want Deny", out.Action)
	}
	if out.Judgment != "destroys_work" || out.Value != 0.92 || out.Condition != ">= 0.85" {
		t.Fatalf("provenance = %q/%v/%q", out.Judgment, out.Value, out.Condition)
	}
}

func TestResolveWithNoulBelowThresholdAllows(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When: map[string]string{"destroys_work": ">= 0.85"}, Action: "deny",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.12},
	}}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", out.Action)
	}
}

// A rm -rf of a build directory is the case the README admits substring
// matching gets wrong; a low noul must leave it allowed.
func TestResolveWithLowNoulAllowsHarmlessCleanup(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When: map[string]string{"destroys_work": ">= 0.85"}, Action: "deny",
	})
	evt := policy.Event{Name: "PreToolUse", Tool: "Bash", Command: "rm -rf ./build"}
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.04},
	}}

	if out := policy.ResolveWith(cfg, evt, res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", out.Action)
	}
}

func TestResolveWithScoreLevelThreshold(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", When: map[string]string{"blast_radius": ">= 2"}, Action: "deny",
	})
	answers := judge.Answers{"blast_radius": {Type: judge.TypeScore, Score: 1.6}}

	if out := policy.ResolveWith(cfg, bashEvent(), policy.Result{Attempted: true, Answers: answers}); out.Action != agent.Allow {
		t.Fatalf("score 1.6 vs >= 2: action = %v, want Allow", out.Action)
	}

	answers["blast_radius"] = judge.Answer{Type: judge.TypeScore, Score: 2.4}
	if out := policy.ResolveWith(cfg, bashEvent(), policy.Result{Attempted: true, Answers: answers}); out.Action != agent.Deny {
		t.Fatalf("score 2.4 vs >= 2: action = %v, want Deny", out.Action)
	}
}

func TestResolveWithChoiceEqualityAndConfidence(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse",
		When: map[string]string{
			"destination":            "== shared",
			"destination.confidence": ">= 0.6",
		},
		Action: "deny",
	})

	// Right choice, confidence below the floor: must not fire.
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destination": {Type: judge.TypeChoice, Choice: "shared", Confidence: 0.4},
	}}
	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("low confidence: action = %v, want Allow", out.Action)
	}

	res.Answers["destination"] = judge.Answer{Type: judge.TypeChoice, Choice: "shared", Confidence: 0.81}
	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Deny {
		t.Fatalf("high confidence: action = %v, want Deny", out.Action)
	}
}

func TestResolveWithMissingAnswerDoesNotFire(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", When: map[string]string{"destroys_work": ">= 0.5"}, Action: "deny",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{}}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", out.Action)
	}
}

// The plain Resolve entry point never attempts judgments, so every when:
// rule is inert — which is how all the pre-judgment tests keep passing
// untouched.
func TestResolveWithoutAnswersSkipsWhenRules(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", When: map[string]string{"destroys_work": ">= 0.5"}, Action: "deny",
	})
	if d := policy.Resolve(cfg, bashEvent()); d.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", d.Action)
	}
}

// When judgments aren't configured at all, on-error must NOT apply: it
// exists for a configured judgment failing at runtime. Otherwise a shared
// policy carrying `on-error: ask` would prompt on every matching call for
// any teammate without an API key.
func TestResolveUnconfiguredJudgmentsIgnoreOnError(t *testing.T) {
	for _, onErr := range []string{"ask", "deny"} {
		cfg := judgedConfig(policy.Rule{
			Event: "PreToolUse", Tools: []string{"Bash"},
			When:    map[string]string{"destroys_work": ">= 0.85"},
			OnError: onErr, Action: "deny",
		})
		// Attempted is false: no key, so the judgment step never ran.
		out := policy.ResolveWith(cfg, bashEvent(), policy.Result{})
		if out.Action != agent.Allow {
			t.Errorf("on-error %q unconfigured: action = %v, want Allow", onErr, out.Action)
		}
	}
}

// The mirror image: once judgments ARE configured, a runtime failure must
// still reach on-error.
func TestResolveConfiguredFailureStillUsesOnError(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When:    map[string]string{"destroys_work": ">= 0.85"},
		OnError: "deny", Action: "deny",
	})
	res := policy.Result{Attempted: true, Err: errors.New("timeout")}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Deny {
		t.Fatalf("action = %v, want Deny", out.Action)
	}
}

// when: ANDs with commands:, so a satisfied judgment cannot rescue a rule
// whose lexical filter missed. This is what makes adding a judgment to an
// existing rule a strictly subtractive edit.
func TestResolveWithWhenAndsWithCommands(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"}, Commands: []string{"git push"},
		When: map[string]string{"destroys_work": ">= 0.5"}, Action: "deny",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.99},
	}}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow (commands filter did not match)", out.Action)
	}
}

func TestResolveWithOnErrorAskOnJudgmentFailure(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When:    map[string]string{"destroys_work": ">= 0.85"},
		OnError: "ask", Action: "deny", Reason: "unverified",
	})
	res := policy.Result{Attempted: true, Err: errors.New("network down")}

	out := policy.ResolveWith(cfg, bashEvent(), res)
	if out.Action != agent.Ask {
		t.Fatalf("action = %v, want Ask", out.Action)
	}
}

func TestResolveWithOnErrorDefaultsToAllow(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When: map[string]string{"destroys_work": ">= 0.85"}, Action: "deny",
	})
	res := policy.Result{Attempted: true, Err: errors.New("network down")}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", out.Action)
	}
}

// on-error must apply only when the clause could not be evaluated, never
// when an answer arrived and simply fell below the threshold.
func TestResolveWithOnErrorIgnoredWhenAnswerBelowThreshold(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When:    map[string]string{"destroys_work": ">= 0.85"},
		OnError: "deny", Action: "deny",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.02},
	}}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", out.Action)
	}
}

func TestResolveWithConfidenceOnNoulIsUnevaluable(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event:  "PreToolUse",
		When:   map[string]string{"destroys_work.confidence": ">= 0.5"},
		Action: "deny",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.99},
	}}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow", out.Action)
	}
}

func TestResolveWithAllWhenConditionsMustHold(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse",
		When: map[string]string{
			"destroys_work": ">= 0.85",
			"blast_radius":  ">= 2",
		},
		Action: "deny",
	})
	res := policy.Result{Attempted: true, Answers: judge.Answers{
		"destroys_work": {Type: judge.TypeNoul, Noul: 0.92},
		"blast_radius":  {Type: judge.TypeScore, Score: 1.0},
	}}

	if out := policy.ResolveWith(cfg, bashEvent(), res); out.Action != agent.Allow {
		t.Fatalf("action = %v, want Allow (blast_radius unmet)", out.Action)
	}
}

func TestCandidatesIgnoresWhenClause(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event: "PreToolUse", Tools: []string{"Bash"},
		When: map[string]string{"destroys_work": ">= 0.85"}, Action: "deny",
	})
	if got := policy.Candidates(cfg, bashEvent()); len(got) != 1 {
		t.Fatalf("candidates = %d, want 1", len(got))
	}
	if got := policy.Candidates(cfg, policy.Event{Name: "PreToolUse", Tool: "Read"}); len(got) != 0 {
		t.Fatalf("candidates = %d, want 0", len(got))
	}
}

func TestQuestionsReturnsUnionWithoutDuplicates(t *testing.T) {
	cfg := policy.Config{Judgments: battery()}
	rules := []policy.Rule{
		{When: map[string]string{"destroys_work": ">= 0.8", "blast_radius": ">= 2"}},
		{When: map[string]string{"blast_radius": ">= 1", "destination": "== shared"}},
		{When: map[string]string{"destination.confidence": ">= 0.5"}},
	}

	qs, missing := policy.Questions(cfg, rules)
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want none", missing)
	}
	if len(qs) != 3 {
		t.Fatalf("questions = %d (%v), want 3", len(qs), qs)
	}
	// A ".confidence" reference must resolve to its base judgment, not to a
	// separate question.
	if _, ok := qs["destination"]; !ok {
		t.Fatalf("questions missing %q: %v", "destination", qs)
	}
}

func TestQuestionsEmptyWhenNoRuleHasWhen(t *testing.T) {
	cfg := policy.Config{Judgments: battery()}
	rules := []policy.Rule{{Commands: []string{"git push"}}, {Paths: []string{".env"}}}

	if qs, _ := policy.Questions(cfg, rules); len(qs) != 0 {
		t.Fatalf("questions = %v, want none", qs)
	}
}

func TestQuestionsReportsUndeclaredJudgment(t *testing.T) {
	cfg := policy.Config{Judgments: battery()}
	rules := []policy.Rule{{When: map[string]string{"typo_here": ">= 0.5"}}}

	qs, missing := policy.Questions(cfg, rules)
	if len(qs) != 0 {
		t.Fatalf("questions = %v, want none", qs)
	}
	if len(missing) != 1 || missing[0] != "typo_here" {
		t.Fatalf("missing = %v", missing)
	}
}

func TestValidateReportsPolicyMistakes(t *testing.T) {
	cfg := policy.Config{
		Judgments: map[string]judge.Question{
			"ok":    {Type: judge.TypeNoul},
			"bogus": {Type: "guess"},
		},
		Rules: []policy.Rule{
			{When: map[string]string{"undeclared": ">= 0.5"}},
			{When: map[string]string{"ok.confidence": ">= 0.5"}},
			{When: map[string]string{"ok": "~ 0.5"}},
			{When: map[string]string{"ok": ">= 0.5"}, OnError: "maybe"},
		},
	}

	errs := cfg.Validate()
	if len(errs) != 5 {
		t.Fatalf("errs = %d, want 5:\n%v", len(errs), errs)
	}
}

func TestValidateAcceptsAGoodConfig(t *testing.T) {
	cfg := judgedConfig(policy.Rule{
		Event:   "PreToolUse",
		When:    map[string]string{"destroys_work": ">= 0.85", "destination.confidence": ">= 0.6"},
		OnError: "ask", Action: "deny",
	})
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("errs = %v, want none", errs)
	}
}

// An unknown field must fail the parse rather than being ignored. Silently
// dropping it turns a policy written for a newer hookmon into a different
// policy: a binary predating `when:` would read a judgment-guarded rule as
// an unconditional deny. Load's error contract is fail-open, so a version
// skew allows everything and says so.
func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	body := "rules:\n  - event: PreToolUse\n    tools: [\"Bash\"]\n    not_a_real_field: 1\n    action: deny\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, found, err := policy.Load(p)
	if !found {
		t.Fatal("found = false, want true")
	}
	if err == nil {
		t.Fatal("err = nil, want a parse error naming the unknown field")
	}
	if len(cfg.Rules) != 0 {
		t.Fatalf("cfg = %+v, want the zero Config so callers fail open", cfg)
	}
}

// A policy using only fields this binary knows must still load cleanly.
func TestLoadAcceptsEveryKnownField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	body := `judgments:
  destroys_work:
    type: noul
    instructions: "q"
    criteria: {"true": "a", "false": "b"}
  blast_radius:
    type: score
    instructions: "q"
    criteria: ["a", "b"]
rules:
  - event: PreToolUse
    agent: claudecode
    tools: ["Bash"]
    paths: [".env"]
    commands: ["npm publish"]
    when: {destroys_work: ">= 0.85"}
    on-error: ask
    action: deny
    reason: "r"
default-action: allow
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := policy.Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 1 || len(cfg.Judgments) != 2 {
		t.Fatalf("cfg = %+v", cfg)
	}
	if errs := cfg.Validate(); len(errs) != 0 {
		t.Fatalf("Validate: %v", errs)
	}
}
