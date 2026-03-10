package shellguard

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/fvckgrimm/shellguard/internal/config"
	"github.com/fvckgrimm/shellguard/internal/engine"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage rule packs",
	Long:  `List, install, update, validate, and manage shellguard rule packs.`,
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all loaded rules and rule packs",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		verbose, _ := cmd.Flags().GetBool("verbose")
		packFilter, _ := cmd.Flags().GetString("pack")
		tagFilter, _ := cmd.Flags().GetString("tag")

		eng, err := engine.New(engine.Options{
			RulePackDirs: cfg.RulePackDirs(),
		})
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}

		packs := eng.LoadedPacks()
		cyan := color.New(color.FgCyan, color.Bold).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		yellow := color.New(color.FgYellow).SprintFunc()
		red := color.New(color.FgRed, color.Bold).SprintFunc()
		dim := color.New(color.Faint).SprintFunc()

		severityColor := map[string]func(...interface{}) string{
			"critical": red,
			"high":     color.New(color.FgRed).SprintFunc(),
			"medium":   yellow,
			"low":      color.New(color.FgCyan).SprintFunc(),
			"info":     dim,
		}

		totalRules := 0
		for _, pack := range packs {
			if packFilter != "" && pack.ID != packFilter {
				continue
			}

			fmt.Printf("\n%s  %s\n", cyan("▸ "+pack.ID), dim("v"+pack.Version))
			fmt.Printf("  %s\n", pack.Description)
			fmt.Printf("  Author: %s  |  %d rules\n", pack.Author, len(pack.Rules))

			if verbose {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				for _, rule := range pack.Rules {
					if tagFilter != "" && !ruleHasTag(rule, tagFilter) {
						continue
					}
					sevFn := severityColor[strings.ToLower(rule.Severity)]
					if sevFn == nil {
						sevFn = dim
					}
					tags := strings.Join(rule.Tags, ", ")
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n",
						sevFn("["+strings.ToUpper(rule.Severity)+"]"),
						green(rule.ID),
						rule.Name,
						dim(tags),
					)
					totalRules++
				}
				_ = w.Flush()
			} else {
				totalRules += len(pack.Rules)
			}
		}

		fmt.Printf("\n%s\n", dim(fmt.Sprintf("Total: %d rules across %d packs", totalRules, len(packs))))
		return nil
	},
}

var rulesValidateCmd = &cobra.Command{
	Use:   "validate [file-or-dir]",
	Short: "Validate rule pack YAML files",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := "."
		if len(args) > 0 {
			target = args[0]
		}

		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed, color.Bold).SprintFunc()

		var files []string
		info, err := os.Stat(target)
		if err != nil {
			return err
		}
		if info.IsDir() {
			err = filepath.Walk(target, func(path string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if !fi.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return err
			}
		} else {
			files = []string{target}
		}

		allOK := true
		for _, f := range files {
			_, err := engine.LoadPackFile(f)
			if err != nil {
				fmt.Printf("%s %s: %v\n", red("✗"), f, err)
				allOK = false
			} else {
				fmt.Printf("%s %s\n", green("✓"), f)
			}
		}

		if !allOK {
			return fmt.Errorf("validation failed")
		}
		fmt.Printf("\n%s All rule files valid\n", green("✓"))
		return nil
	},
}

var rulesNewCmd = &cobra.Command{
	Use:   "new [name]",
	Short: "Scaffold a new rule pack",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		outDir, _ := cmd.Flags().GetString("dir")
		if outDir == "" {
			outDir = "."
		}

		filename := filepath.Join(outDir, name+".yaml")
		if _, err := os.Stat(filename); err == nil {
			return fmt.Errorf("file already exists: %s", filename)
		}

		template := fmt.Sprintf(`# shellguard rule pack: %s
# See https://github.com/fvckgrimm/shellguard/docs/rules.md for full spec

id: %s
name: "%s"
version: "0.1.0"
description: "Describe what this rule pack detects"
author: "Your Name"
tags:
  - custom

rules:
  - id: %s-001
    name: "Example Rule"
    description: "Detects an example dangerous pattern"
    severity: high   # critical, high, medium, low, info
    tags:
      - example
    # Match modes: regex, multi_regex, keyword, ast (future)
    match:
      mode: regex
      pattern: 'your_regex_here'
      # flags: [case_insensitive]  # optional
      # negate: false              # flip match (alert if NOT found)
    # Optional: only trigger if context also matches
    # context:
    #   require_any:
    #     - 'context_pattern_1'
    #     - 'context_pattern_2'
    remediation: "Explain how to fix or avoid this pattern"
    references:
      - https://example.com/cve-or-writeup

  - id: %s-002
    name: "Multi-pattern Example"
    description: "Fires if ALL patterns match (AND logic)"
    severity: medium
    tags:
      - example
    match:
      mode: multi_regex
      logic: all   # all = AND, any = OR
      patterns:
        - 'first_pattern'
        - 'second_pattern'
    remediation: "Explain how to remediate"
`, name, name, name, name, name)

		if err := os.WriteFile(filename, []byte(template), 0644); err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}

		green := color.New(color.FgGreen).SprintFunc()
		fmt.Printf("%s Created %s\n", green("✓"), filename)
		fmt.Printf("  Edit the file, then validate with: shellguard rules validate %s\n", filename)
		return nil
	},
}

var rulesTagsCmd = &cobra.Command{
	Use:   "tags",
	Short: "List all available rule tags",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		eng, err := engine.New(engine.Options{RulePackDirs: cfg.RulePackDirs()})
		if err != nil {
			return err
		}

		tags := eng.AllTags()
		cyan := color.New(color.FgCyan).SprintFunc()
		for _, t := range tags {
			count := eng.CountByTag(t)
			fmt.Printf("  %s  %s\n", cyan(t), color.New(color.Faint).Sprintf("(%d rules)", count))
		}
		return nil
	},
}

func init() {
	rulesListCmd.Flags().BoolP("verbose", "v", false, "Show individual rules within each pack")
	rulesListCmd.Flags().String("pack", "", "Filter to a specific pack ID")
	rulesListCmd.Flags().String("tag", "", "Filter rules by tag")

	rulesNewCmd.Flags().String("dir", ".", "Directory to create the rule pack in")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesValidateCmd)
	rulesCmd.AddCommand(rulesNewCmd)
	rulesCmd.AddCommand(rulesTagsCmd)
}

func ruleHasTag(rule engine.Rule, tag string) bool {
	for _, t := range rule.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
