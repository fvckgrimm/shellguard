package shellguard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/fvckgrimm/shellguard/internal/ai"
	"github.com/fvckgrimm/shellguard/internal/analyzer"
	"github.com/fvckgrimm/shellguard/internal/config"
	"github.com/fvckgrimm/shellguard/internal/engine"
	"github.com/fvckgrimm/shellguard/internal/output"
	"github.com/fvckgrimm/shellguard/internal/resolver"
)

var scanCmd = &cobra.Command{
	Use:   "scan [flags] [file]",
	Short: "Scan a script or command for security risks",
	Long: `Scan a script, file, or piped content for security risks.

Positional argument or -f flag can specify a file. Omit both to read from stdin.

Examples:
  # Pipe from curl (the dangerous pattern)
  curl https://example.com/install.sh | shellguard scan

  # Scan a local file
  shellguard scan -f script.sh
  shellguard scan script.sh

  # AI-powered deep analysis
  shellguard scan -f script.sh --ai

  # Pipe-gate: scan then execute only if approved
  curl https://example.com/install.sh | shellguard scan --passthrough | bash

  # Non-interactive for agent pipelines (exit 0=safe, 1=risky)
  shellguard scan -f script.sh --non-interactive

  # Output as JSON for programmatic use
  shellguard scan -f script.sh --format json

  # Only run specific rule tags
  shellguard scan -f script.sh --tags reverse_shell,credential_theft

  # Exclude rule tags
  shellguard scan -f script.sh --exclude-tags low

  # Set minimum severity to report
  shellguard scan -f script.sh --severity medium
`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	f := scanCmd.Flags()

	// Input
	f.StringP("file", "f", "", "File to scan (use - for stdin)")

	// Behavior
	f.BoolP("yes", "y", false, "Auto-approve if severity below threshold")
	f.BoolP("non-interactive", "n", false, "Never prompt; exit 0=clean, 1=risky, 2=error")
	f.Bool("passthrough", false, "Write content to stdout if approved (pipe-gate mode)")
	f.Bool("no-recurse", false, "Disable recursive file reference scanning")
	f.Int("depth", 5, "Max recursion depth for referenced files")

	// AI
	f.Bool("ai", false, "Enable AI-powered deep analysis (requires API key)")
	f.Bool("no-ai", false, "Disable AI analysis even if enabled in config")
	f.String("ai-model", "", "AI model to use (overrides config)")
	f.String("ai-provider", "", "AI provider: anthropic, openai (default: anthropic)")

	// Rule filtering
	f.StringSlice("tags", nil, "Only run rules with these tags (comma-separated)")
	f.StringSlice("exclude-tags", nil, "Skip rules with these tags")
	f.StringSlice("rule-packs", nil, "Only load these rule packs (default: all enabled)")
	f.String("severity", "low", "Minimum severity to report: critical, high, medium, low, info")

	// Output
	f.String("format", "pretty", "Output format: pretty, json, sarif, markdown")
	f.StringP("output", "o", "", "Write report to file (in addition to stdout)")
	f.Bool("no-color", false, "Disable color output")
}

func runScan(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	flags := cmd.Flags()

	// ── Resolve input source ────────────────────────────────────────────────
	filePath, _ := flags.GetString("file")
	if filePath == "" && len(args) > 0 {
		filePath = args[0]
	}

	var content []byte
	var sourceLabel string

	switch {
	case filePath != "" && filePath != "-":
		content, err = os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("cannot read file %q: %w", filePath, err)
		}
		sourceLabel = filePath

	case filePath == "-" || isStdinPiped():
		content, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("cannot read stdin: %w", err)
		}
		sourceLabel = "<stdin>"

	default:
		return fmt.Errorf("no input provided — pipe content or specify a file\n\n  Usage: curl https://example.com/install.sh | shellguard scan\n         shellguard scan -f script.sh")
	}

	if len(strings.TrimSpace(string(content))) == 0 {
		fmt.Fprintln(os.Stderr, "⚠  empty input, nothing to scan")
		return nil
	}

	// ── Build scan options from flags ───────────────────────────────────────
	tags, _ := flags.GetStringSlice("tags")
	excludeTags, _ := flags.GetStringSlice("exclude-tags")
	rulePacks, _ := flags.GetStringSlice("rule-packs")
	minSeverity, _ := flags.GetString("severity")
	depth, _ := flags.GetInt("depth")
	noRecurse, _ := flags.GetBool("no-recurse")
	format, _ := flags.GetString("format")
	outFile, _ := flags.GetString("output")
	passthrough, _ := flags.GetBool("passthrough")
	nonInteractive, _ := flags.GetBool("non-interactive")
	autoYes, _ := flags.GetBool("yes")
	noColor, _ := flags.GetBool("no-color")
	quiet, _ := flags.GetBool("quiet")
	if viper.GetBool("no_color") {
		noColor = true
	}
	if viper.GetBool("quiet") {
		quiet = true
	}

	// AI flags
	useAI := cfg.AI.Enabled
	if v, _ := flags.GetBool("ai"); v {
		useAI = true
	}
	if v, _ := flags.GetBool("no-ai"); v {
		useAI = false
	}
	aiModel, _ := flags.GetString("ai-model")
	if aiModel == "" {
		aiModel = cfg.AI.Model
	}
	aiProvider, _ := flags.GetString("ai-provider")
	if aiProvider == "" {
		aiProvider = cfg.AI.Provider
	}

	// ── Load rule engine ────────────────────────────────────────────────────
	eng, err := engine.New(engine.Options{
		RulePackDirs: cfg.RulePackDirs(),
		EnabledPacks: rulePacks,
		Tags:         tags,
		ExcludeTags:  excludeTags,
		MinSeverity:  engine.ParseSeverity(minSeverity),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize rule engine: %w", err)
	}

	// ── Run scan ────────────────────────────────────────────────────────────
	scanOpts := analyzer.ScanOptions{
		Content:   string(content),
		Source:    sourceLabel,
		MaxDepth:  depth,
		NoRecurse: noRecurse,
		Engine:    eng,
		WorkDir:   workDir(filePath),
	}

	printer := output.NewPrinter(output.PrinterOptions{
		Format:  format,
		NoColor: noColor,
		Quiet:   quiet,
		OutFile: outFile,
	})

	if !quiet && format == "pretty" {
		printer.Banner()
		printer.ScanHeader(sourceLabel, content)
	}

	report, err := analyzer.Scan(scanOpts)
	if err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	// ── AI analysis ─────────────────────────────────────────────────────────
	var aiResult *ai.Result
	if useAI {
		aiClient, clientErr := ai.NewClient(ai.ClientOptions{
			Provider: aiProvider,
			Model:    aiModel,
			APIKey:   cfg.AI.APIKey(),
		})
		if clientErr != nil {
			fmt.Fprintf(os.Stderr, "⚠  AI analysis unavailable: %v\n", clientErr)
		} else {
			if !quiet && format == "pretty" {
				printer.AIHeader(aiModel)
			}
			aiResult, err = aiClient.Analyze(string(content), report.Findings)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠  AI analysis failed: %v\n", err)
			}
		}
	}

	// ── Resolve referenced files (recursive scan) ───────────────────────────
	if !noRecurse {
		refResults := resolver.ScanRefs(string(content), sourceLabel, scanOpts, depth)
		for _, r := range refResults {
			report.Merge(r)
		}
	}

	report.AIResult = aiResult

	// ── Print report ─────────────────────────────────────────────────────────
	if err := printer.Report(report); err != nil {
		return fmt.Errorf("output error: %w", err)
	}

	// ── Decision ─────────────────────────────────────────────────────────────
	verdict := report.Verdict()
	proceed := decideAndPrompt(verdict, report, nonInteractive, autoYes, printer)

	if proceed {
		printer.Approved()
		if passthrough {
			// Write original content to stdout for piping
			os.Stdout.Write(content)
		}
		// Log to audit trail
		_ = cfg.AuditLog(sourceLabel, verdict.String(), len(report.Findings), contentHash(content))
		os.Exit(0)
	} else {
		printer.Rejected()
		_ = cfg.AuditLog(sourceLabel, verdict.String(), len(report.Findings), contentHash(content))
		os.Exit(1)
	}

	return nil
}

func decideAndPrompt(verdict engine.Verdict, report *analyzer.Report, nonInteractive, autoYes bool, printer *output.Printer) bool {
	printer.Verdict(verdict, report)

	if nonInteractive {
		switch verdict {
		case engine.VerdictClean, engine.VerdictInfo, engine.VerdictLow:
			return true
		default:
			return false
		}
	}

	if autoYes && verdict != engine.VerdictCritical && verdict != engine.VerdictInjection {
		return true
	}

	return printer.Prompt(verdict)
}

func isStdinPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) == 0
}

func workDir(filePath string) string {
	if filePath == "" || filePath == "-" {
		wd, _ := os.Getwd()
		return wd
	}
	// Get parent dir of the file
	parts := strings.Split(filePath, "/")
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], "/")
	}
	wd, _ := os.Getwd()
	return wd
}

func contentHash(b []byte) string {
	// Simple FNV-1a hash for audit log
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

// promptLine reads a line from stdin for the interactive prompt
func promptLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}
