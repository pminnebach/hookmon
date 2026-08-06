package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"hookmon/agent"
	"hookmon/relay"
)

// NewSendCmd creates the send subcommand (invoked by agent hooks).
func NewSendCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send",
		Short: "Read a hook payload from stdin and forward it to the listener",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var cfg relay.Config
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
				_ = p.Acknowledge(cmd.OutOrStdout())
				return nil
			}

			// Fail-open: relay errors go to stderr; always acknowledge.
			_ = relay.Send(cmd.Context(), cfg, payload, cmd.ErrOrStderr())
			if err := p.Acknowledge(cmd.OutOrStdout()); err != nil {
				fmt.Fprintf(os.Stderr, "hookmon: acknowledge: %v\n", err)
			}
			return nil
		},
	}

	cmd.Flags().String("agent", "cursor", "agent provider name")
	return cmd
}
