package shellguard

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/fvckgrimm/shellguard/internal/config"
)

var cfgFile string

var rootCmd = &cobra.Command{
	Use:   "shellguard",
	Short: "🛡 Script & command security scanner",
	Long: `shellguard — security scanner for shell scripts, curl one-liners, and AI agent skill files.

Pipe content into shellguard before executing, or scan files directly.
Rule packs are YAML-based and fully extensible (like Nuclei templates).

Examples:
  curl https://example.com/install.sh | shellguard scan
  shellguard scan -f script.sh
  shellguard scan -f script.sh --ai
  shellguard scan --passthrough -f deploy.sh | bash
  shellguard rules list
  shellguard rules install community/k8s-scripts
`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.config/shellguard/config.yaml)")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable color output")
	rootCmd.PersistentFlags().Bool("quiet", false, "Suppress banner and progress messages")
	rootCmd.PersistentFlags().String("log-level", "info", "Log level: debug, info, warn, error")

	_ = viper.BindPFlag("no_color", rootCmd.PersistentFlags().Lookup("no-color"))
	_ = viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		cfgDir, err := config.DefaultConfigDir()
		if err == nil {
			viper.AddConfigPath(cfgDir)
			viper.SetConfigName("config")
			viper.SetConfigType("yaml")
		}
	}

	viper.SetEnvPrefix("SHELLGUARD")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "Warning: error reading config: %v\n", err)
		}
	}
}
