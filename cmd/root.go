package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"hookmon/agent"
	_ "hookmon/agent/claudecode" // register claudecode provider
	_ "hookmon/agent/cursor"     // register cursor provider
	"hookmon/policy"
	"hookmon/relay"
)

// config is hookmon's full per-invocation configuration: relay.Config
// (logging) plus where to find the policy file.
type config struct {
	relay.Config `mapstructure:",squash"`
	PolicyFile   string `mapstructure:"policy-file"`
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
			evt := policy.ParseEvent(cfg.Agent, payload)
			decision := policy.Resolve(policyCfg, evt)

			if err := p.Acknowledge(cmd.OutOrStdout(), evt.Name, decision); err != nil {
				fmt.Fprintf(os.Stderr, "hookmon: acknowledge: %v\n", err)
			}
			return nil
		},
	}

	rootCmd.Flags().String("config", "", "config file path")
	rootCmd.Flags().String("agent", "cursor", "agent provider name")
	rootCmd.Flags().String("log-file", "", "path to log file (absolute or relative); unset disables logging")
	rootCmd.Flags().String("policy-file", ".hookmon-policy.yaml", "path to policy file (YAML); missing file disables blocking")

	v.SetDefault("agent", "cursor")
	v.SetDefault("log-file", "")
	v.SetDefault("policy-file", ".hookmon-policy.yaml")

	return rootCmd
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
