package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"hookmon/agent"
	_ "hookmon/agent/claudecode" // register claudecode provider
	_ "hookmon/agent/cursor"     // register cursor provider
	"hookmon/judge"
	"hookmon/policy"
	"hookmon/relay"
)

// config is hookmon's full per-invocation configuration: relay.Config
// (logging), where to find the policy file, and how to reach TypeSafe for
// semantic judgments.
//
// TypeSafeAPIKey deliberately has no flag. The hook command line is embedded
// in .claude/settings.json, which the README tells people to check in, so a
// flag would invite committing the key (and would expose it in ps). It comes
// from HOOKMON_TYPESAFE_API_KEY or ~/.hookmon.yaml only, and never from the
// shared policy file.
type config struct {
	relay.Config      `mapstructure:",squash"`
	PolicyFile        string        `mapstructure:"policy-file"`
	TypeSafeAPIKey    string        `mapstructure:"typesafe-api-key"`
	TypeSafeEndpoint  string        `mapstructure:"typesafe-endpoint"`
	TypeSafeModel     string        `mapstructure:"typesafe-model"`
	TypeSafeTimeout   time.Duration `mapstructure:"typesafe-timeout"`
	TypeSafeCacheDir  string        `mapstructure:"typesafe-cache-dir"`
	TypeSafeCacheTTL  time.Duration `mapstructure:"typesafe-cache-ttl"`
	TypeSafeSendInput bool          `mapstructure:"typesafe-send-content"`
}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// NewRootCmd builds the hookmon command with a fresh Viper instance.
//
// hookmon has no subcommands: invoking it reads a hook payload from stdin,
// logs it, and acknowledges. There is no server to start and nothing to
// dial — each invocation is independent.
func NewRootCmd() *cobra.Command {
	v := viper.New()

	rootCmd := &cobra.Command{
		Use:           "hookmon",
		Short:         "Read a coding-agent hook payload from stdin and log it to a file",
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(v, cmd)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg config
			if err := v.Unmarshal(&cfg); err != nil {
				return fmt.Errorf("decoding config: %w", err)
			}
			if cfg.Agent == "" {
				cfg.Agent = "cursor"
			}

			p, err := agent.Lookup(cfg.Agent)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: %v\n", err)
				_, _ = io.WriteString(cmd.OutOrStdout(), "{}\n")
				return nil
			}

			payload, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: read stdin: %v\n", err)
				_ = p.Acknowledge(cmd.OutOrStdout(), "", agent.Decision{})
				return nil
			}

			// Fail-open: logging errors go to stderr; always acknowledge.
			if err := relay.Log(cfg.Config, payload); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: %v\n", err)
			}

			// Fail-open: a missing or malformed policy file behaves exactly
			// like no policy configured (allow everything).
			policyCfg, _, err := policy.Load(cfg.PolicyFile)
			if err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: policy: %v\n", err)
				policyCfg = policy.Config{}
			}
			for _, e := range policyCfg.Validate() {
				fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: policy: %v\n", e)
			}

			evt := policy.ParseEvent(cfg.Agent, payload)
			res := runJudgments(cmd, cfg, policyCfg, evt)
			decision := policy.ResolveWith(policyCfg, evt, res)

			// Fail-open: policy-log write errors go to stderr; never block
			// acknowledgment.
			if decision.Action == agent.Deny {
				rec := relay.PolicyDecision{
					Time:              time.Now().UTC().Format(time.RFC3339),
					Agent:             cfg.Agent,
					Event:             evt.Name,
					Tool:              evt.Tool,
					Path:              evt.Path,
					Command:           evt.Command,
					Action:            decision.Action.String(),
					Reason:            decision.Reason,
					Judgment:          decision.Judgment,
					JudgmentValue:     decision.Value,
					JudgmentCondition: decision.Condition,
				}
				if err := relay.LogPolicyDecision(cfg.Config, rec); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: policy log: %v\n", err)
				}
			}

			if err := p.Acknowledge(cmd.OutOrStdout(), evt.Name, decision.Decision); err != nil {
				fmt.Fprintf(os.Stderr, "hookmon: acknowledge: %v\n", err)
			}
			return nil
		},
	}

	rootCmd.Flags().String("config", "", "config file path")
	rootCmd.Flags().String("agent", "cursor", "agent provider name")
	rootCmd.Flags().String("log-file", "", "path to log file (absolute or relative); unset disables logging")
	rootCmd.Flags().String("policy-file", ".hookmon-policy.yaml", "path to policy file (YAML); missing file disables blocking")
	rootCmd.Flags().String("policy-log-file", ".hookmon-policy.log", "path to policy decision log file (denied actions only); empty disables it")

	rootCmd.Flags().Duration("typesafe-timeout", judge.DefaultTimeout, "budget for one semantic judgment call; it blocks the agent's tool call")
	rootCmd.Flags().String("typesafe-model", judge.DefaultModel, "TypeSafe System One model")
	rootCmd.Flags().Duration("typesafe-cache-ttl", 24*time.Hour, "how long to reuse a cached judgment; 0 disables the cache")
	rootCmd.Flags().String("typesafe-cache-dir", "", "judgment cache directory (default: user cache dir)")
	rootCmd.Flags().Bool("typesafe-send-content", false, "send file/message content in tool_input to TypeSafe (off by default)")

	v.SetDefault("agent", "cursor")
	v.SetDefault("log-file", "")
	v.SetDefault("policy-file", ".hookmon-policy.yaml")
	v.SetDefault("policy-log-file", ".hookmon-policy.log")

	// These two have no flag on purpose: the API key must never reach a
	// checked-in command line, and the endpoint is only overridden by tests
	// and self-hosted proxies. SetDefault is still required — v.Unmarshal
	// only walks keys viper already knows about, so a value supplied purely
	// through AutomaticEnv is invisible without it.
	v.SetDefault("typesafe-api-key", "")
	v.SetDefault("typesafe-endpoint", judge.DefaultEndpoint)

	v.SetDefault("typesafe-timeout", judge.DefaultTimeout)
	v.SetDefault("typesafe-model", judge.DefaultModel)
	v.SetDefault("typesafe-cache-ttl", 24*time.Hour)
	v.SetDefault("typesafe-cache-dir", "")
	v.SetDefault("typesafe-send-content", false)

	return rootCmd
}

// runJudgments performs the semantic judgment step for one hook event.
//
// It returns a zero Result without touching the network whenever no rule
// that already matches lexically carries a When clause. That is the property
// that keeps substring-only policies exactly as fast as they were before
// judgments existed — which matters because this runs inside PreToolUse,
// blocking the agent's tool call.
//
// Every failure is fail-open: warn on stderr and return the error in the
// Result, letting each rule apply its own on-error action.
func runJudgments(cmd *cobra.Command, cfg config, policyCfg policy.Config, evt policy.Event) policy.Result {
	candidates := policy.Candidates(policyCfg, evt)
	questions, missing := policy.Questions(policyCfg, candidates)
	for _, id := range missing {
		fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: judge: no judgment declared for %q\n", id)
	}
	if len(questions) == 0 {
		return policy.Result{}
	}

	warn := func(err error) policy.Result {
		// Name the skipped judgments: a network partition silently turning
		// every judgment rule off at once is the highest-consequence
		// failure here, so it needs to be loud.
		fmt.Fprintf(cmd.ErrOrStderr(), "hookmon: judge: %v (%d judgment(s) not evaluated)\n", err, len(questions))
		return policy.Result{Err: err}
	}

	if cfg.TypeSafeAPIKey == "" {
		return warn(judge.ErrNoAPIKey)
	}

	timeout := cfg.TypeSafeTimeout
	if timeout <= 0 {
		timeout = judge.DefaultTimeout
	}

	var client judge.Client = &judge.HTTPClient{
		APIKey:   cfg.TypeSafeAPIKey,
		Endpoint: cfg.TypeSafeEndpoint,
		HTTP:     &http.Client{Timeout: timeout},
	}
	if dir := cacheDir(cfg); dir != "" && cfg.TypeSafeCacheTTL > 0 {
		client = &judge.Cache{Next: client, Dir: dir, TTL: cfg.TypeSafeCacheTTL}
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()

	state := judge.BuildState(judge.Input{
		Agent:     evt.Agent,
		Event:     evt.Name,
		Tool:      evt.Tool,
		Cwd:       evt.Cwd,
		ToolInput: evt.ToolInput,
	}, cfg.TypeSafeSendInput)

	answers, err := client.Ask(ctx, judge.Request{
		Model:     cfg.TypeSafeModel,
		State:     state,
		Questions: questions,
	})
	if err != nil {
		return warn(err)
	}
	return policy.Result{Answers: answers}
}

// cacheDir resolves the judgment cache directory. It deliberately defaults
// outside the working tree: a cache inside the repo would show up in git
// status on every tool call.
func cacheDir(cfg config) string {
	if cfg.TypeSafeCacheDir != "" {
		return cfg.TypeSafeCacheDir
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "hookmon", "judgments")
}

func initConfig(v *viper.Viper, cmd *cobra.Command) error {
	if cfgFile, _ := cmd.Flags().GetString("config"); cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(home)
		}
		v.AddConfigPath(".")
		v.SetConfigType("yaml")
		v.SetConfigName(".hookmon")
	}

	v.SetEnvPrefix("HOOKMON")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("reading config: %w", err)
		}
	}

	return v.BindPFlags(cmd.Flags())
}
