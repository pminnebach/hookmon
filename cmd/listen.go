package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"hookmon/relay"
)

// NewListenCmd creates the listen subcommand.
func NewListenCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "listen",
		Short: "Listen for hook envelopes and print them to the console",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg relay.Config
			if err := v.Unmarshal(&cfg); err != nil {
				return fmt.Errorf("decoding config: %w", err)
			}

			out := cmd.OutOrStdout()
			if cfg.LogFile != "" {
				f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
				if err != nil {
					return fmt.Errorf("open log file %s: %w", cfg.LogFile, err)
				}
				defer f.Close()
				out = f
			}
			return relay.Listen(cmd.Context(), cfg, out)
		},
	}
	return cmd
}
