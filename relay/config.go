package relay

// Config is the typed configuration for hookmon.
type Config struct {
	Agent         string `mapstructure:"agent"`
	LogFile       string `mapstructure:"log-file"`
	PolicyLogFile string `mapstructure:"policy-log-file"`
}
