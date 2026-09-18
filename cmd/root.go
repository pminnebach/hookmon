package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	_ "hookmon/agent/claudecode" // register claudecode provider
	_ "hookmon/agent/cursor"     // register cursor provider
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// NewRootCmd builds the command tree with a fresh Viper instance.
func NewRootCmd() *cobra.Command {
	v := viper.New()

	rootCmd := &cobra.Command{
		Use:           "hookmon",
		Short:         "Relay coding-agent hook payloads to a local listener",
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return initConfig(v, cmd)
		},
	}

	rootCmd.PersistentFlags().String("config", "", "config file path")
	rootCmd.PersistentFlags().String("addr", "127.0.0.1:9473", "listener address")
	rootCmd.PersistentFlags().String("log-file", "", "path to log file (listen output; absolute or relative)")

	v.SetDefault("addr", "127.0.0.1:9473")
	v.SetDefault("agent", "cursor")
	v.SetDefault("log-file", "")

	rootCmd.AddCommand(NewSendCmd(v))
	rootCmd.AddCommand(NewListenCmd(v))
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
