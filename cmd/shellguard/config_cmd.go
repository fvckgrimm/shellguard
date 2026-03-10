package shellguard

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/fvckgrimm/shellguard/internal/config"
)

// ── Version ──────────────────────────────────────────────────────────────────

var (
	Version   = "0.1.0"
	Commit    = "dev"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print shellguard version",
	Run: func(cmd *cobra.Command, args []string) {
		cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
		dim := color.New(color.Faint).SprintFunc()
		fmt.Printf("%s %s  %s\n",
			cyan("shellguard"),
			Version,
			dim(fmt.Sprintf("commit:%s built:%s", Commit, BuildDate)),
		)
	},
}

// ── Config ───────────────────────────────────────────────────────────────────

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage shellguard configuration",
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		b, err := yaml.Marshal(cfg)
		if err != nil {
			return err
		}
		fmt.Printf("# Config file: %s\n\n%s", viper.ConfigFileUsed(), string(b))
		return nil
	},
}

var configSetCmd = &cobra.Command{
	Use:   "set <key> <value>",
	Short: "Set a configuration value",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		key, val := args[0], args[1]
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if err := cfg.Set(key, val); err != nil {
			return err
		}
		green := color.New(color.FgGreen).SprintFunc()
		fmt.Printf("%s %s = %s\n", green("✓"), key, val)
		return nil
	},
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default config file",
	RunE: func(cmd *cobra.Command, args []string) error {
		path, err := config.Init()
		if err != nil {
			return err
		}
		green := color.New(color.FgGreen).SprintFunc()
		fmt.Printf("%s Config initialized at %s\n", green("✓"), path)
		fmt.Printf("  Edit to customize AI settings, rule packs, severity thresholds, and more.\n")
		return nil
	},
}

var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show config file path",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := config.DefaultConfigDir()
		if err != nil {
			return err
		}
		fmt.Println(dir + "/config.yaml")
		return nil
	},
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configPathCmd)
}
