package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config is the top-level shellguard configuration struct
type Config struct {
	AI           AIConfig     `yaml:"ai"          mapstructure:"ai"`
	Rules        RulesConfig  `yaml:"rules"       mapstructure:"rules"`
	Scan         ScanConfig   `yaml:"scan"        mapstructure:"scan"`
	Output       OutputConfig `yaml:"output"      mapstructure:"output"`
	AuditLogPath string       `yaml:"audit_log"   mapstructure:"audit_log"`
}

type AIConfig struct {
	Enabled   bool   `yaml:"enabled"      mapstructure:"enabled"`
	Provider  string `yaml:"provider"     mapstructure:"provider"`
	Model     string `yaml:"model"        mapstructure:"model"`
	APIKeyEnv string `yaml:"api_key_env"  mapstructure:"api_key_env"`
	Timeout   int    `yaml:"timeout_secs" mapstructure:"timeout_secs"`
}

type RulesConfig struct {
	BuiltinDir string   `yaml:"builtin_dir"  mapstructure:"builtin_dir"`
	CustomDirs []string `yaml:"custom_dirs"  mapstructure:"custom_dirs"`
	Disabled   []string `yaml:"disabled"     mapstructure:"disabled"`
}

type ScanConfig struct {
	MaxRecursionDepth int      `yaml:"max_depth"          mapstructure:"max_depth"`
	DefaultSeverity   string   `yaml:"default_severity"   mapstructure:"default_severity"`
	DefaultTags       []string `yaml:"default_tags"       mapstructure:"default_tags"`
	ExcludeTags       []string `yaml:"exclude_tags"       mapstructure:"exclude_tags"`
}

type OutputConfig struct {
	Format  string `yaml:"format"    mapstructure:"format"`
	NoColor bool   `yaml:"no_color"  mapstructure:"no_color"`
}

// Defaults
var defaultConfig = Config{
	AI: AIConfig{
		Enabled:   false,
		Provider:  "anthropic",
		Model:     "claude-sonnet-4-20250514",
		APIKeyEnv: "ANTHROPIC_API_KEY",
		Timeout:   45,
	},
	Rules: RulesConfig{},
	Scan: ScanConfig{
		MaxRecursionDepth: 5,
		DefaultSeverity:   "low",
	},
	Output: OutputConfig{
		Format: "pretty",
	},
}

func Load() (*Config, error) {
	cfg := defaultConfig

	if err := viper.Unmarshal(&cfg); err != nil {
		return &cfg, nil // return defaults on unmarshal failure
	}

	return &cfg, nil
}

func (c *Config) APIKey() string {
	return c.AI.APIKey()
}

func (a *AIConfig) APIKey() string {
	env := a.APIKeyEnv
	if env == "" {
		env = "ANTHROPIC_API_KEY"
	}
	key := os.Getenv(env)
	if key != "" {
		return key
	}
	// Also try OPENAI_API_KEY for openai provider
	if strings.EqualFold(a.Provider, "openai") {
		return os.Getenv("OPENAI_API_KEY")
	}
	return ""
}

func (c *Config) RulePackDirs() []string {
	var dirs []string

	// 1. Built-in rules: explicit override in config
	builtinDir := c.Rules.BuiltinDir

	if builtinDir == "" {
		// Try cwd/rules/builtin first — works for `go run` and dev
		if cwd, err := os.Getwd(); err == nil {
			candidate := filepath.Join(cwd, "rules", "builtin")
			if _, err := os.Stat(candidate); err == nil {
				builtinDir = candidate
			}
		}
	}

	if builtinDir == "" {
		// Try next to the actual binary (installed)
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "rules", "builtin")
			if _, err := os.Stat(candidate); err == nil {
				builtinDir = candidate
			}
		}
	}

	if builtinDir == "" {
		// Fall back to XDG config dir
		if cfgDir, err := DefaultConfigDir(); err == nil {
			builtinDir = filepath.Join(cfgDir, "rules", "builtin")
		}
	}

	if builtinDir != "" {
		dirs = append(dirs, builtinDir)
	}

	// 2. Community rules: cwd/rules/community for go run / dev
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "rules", "community")
		if _, err := os.Stat(candidate); err == nil {
			dirs = append(dirs, candidate)
		}
	}

	// 3. Custom user rule dirs from config
	dirs = append(dirs, c.Rules.CustomDirs...)

	// 4. XDG community packs dir
	if cfgDir, err := DefaultConfigDir(); err == nil {
		communityDir := filepath.Join(cfgDir, "rules", "community")
		if _, err := os.Stat(communityDir); err == nil {
			dirs = append(dirs, communityDir)
		}
	}

	return dirs
}

func (c *Config) Set(key, value string) error {
	switch key {
	case "ai.enabled":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid bool: %s", value)
		}
		c.AI.Enabled = b
	case "ai.model":
		c.AI.Model = value
	case "ai.provider":
		c.AI.Provider = value
	case "ai.api_key_env":
		c.AI.APIKeyEnv = value
	case "scan.max_depth":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid int: %s", value)
		}
		c.Scan.MaxRecursionDepth = n
	case "scan.default_severity":
		c.Scan.DefaultSeverity = value
	case "output.format":
		c.Output.Format = value
	case "output.no_color":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid bool: %s", value)
		}
		c.Output.NoColor = b
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}

	return c.save()
}

func (c *Config) save() error {
	cfgDir, err := DefaultConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfgDir, 0750); err != nil {
		return err
	}
	path := filepath.Join(cfgDir, "config.yaml")
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0640)
}

func DefaultConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "shellguard"), nil
}

func Init() (string, error) {
	cfgDir, err := DefaultConfigDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(cfgDir, 0750); err != nil {
		return "", fmt.Errorf("cannot create config dir: %w", err)
	}

	// Create rules subdirs
	for _, sub := range []string{"rules/builtin", "rules/community", "rules/custom"} {
		_ = os.MkdirAll(filepath.Join(cfgDir, sub), 0750)
	}

	path := filepath.Join(cfgDir, "config.yaml")
	if _, err := os.Stat(path); err == nil {
		return path, nil // already exists
	}

	b, err := yaml.Marshal(defaultConfig)
	if err != nil {
		return "", err
	}

	header := []byte("# shellguard configuration\n# Run 'shellguard config set <key> <value>' to modify\n# See https://github.com/fvckgrimm/shellguard for full docs\n\n")
	if err := os.WriteFile(path, append(header, b...), 0640); err != nil {
		return "", fmt.Errorf("cannot write config: %w", err)
	}

	return path, nil
}

// AuditLog writes a scan event to the audit log
func (c *Config) AuditLog(source, verdict string, findingsCount int, hash string) error {
	logPath := c.AuditLogPath
	if logPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		logPath = filepath.Join(home, ".local", "share", "shellguard", "audit.log")
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0750); err != nil {
		return err
	}

	entry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"source":    source,
		"verdict":   verdict,
		"findings":  findingsCount,
		"hash":      hash,
	}

	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, string(b))
	return err
}
