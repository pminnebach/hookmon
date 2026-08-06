package relay

// Config is the typed configuration for send/listen.
type Config struct {
	Addr    string `mapstructure:"addr"`
	Agent   string `mapstructure:"agent"`
	LogFile string `mapstructure:"log-file"`
}
