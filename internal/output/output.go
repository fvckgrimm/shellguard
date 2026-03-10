package output

import (
	"bufio"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"

	"github.com/fvckgrimm/shellguard/internal/ai"
	"github.com/fvckgrimm/shellguard/internal/analyzer"
	"github.com/fvckgrimm/shellguard/internal/engine"
)

type PrinterOptions struct {
	Format  string
	NoColor bool
	Quiet   bool
	OutFile string
}

type Printer struct {
	opts    PrinterOptions
	out     io.Writer
	fileOut io.Writer
}

func NewPrinter(opts PrinterOptions) *Printer {
	if opts.NoColor {
		color.NoColor = true
	}

	var fileOut io.Writer
	if opts.OutFile != "" {
		f, err := os.Create(opts.OutFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot create output file %s: %v\n", opts.OutFile, err)
		} else {
			fileOut = f
		}
	}

	return &Printer{
		opts:    opts,
		out:     os.Stderr,
		fileOut: fileOut,
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var (
	cRed      = color.New(color.FgRed, color.Bold).SprintFunc()
	cRedPlain = color.New(color.FgRed).SprintFunc()
	cYellow   = color.New(color.FgYellow).SprintFunc()
	cGreen    = color.New(color.FgGreen, color.Bold).SprintFunc()
	cCyan     = color.New(color.FgCyan).SprintFunc()
	cBold     = color.New(color.Bold).SprintFunc()
	cDim      = color.New(color.Faint).SprintFunc()
	cMagenta  = color.New(color.FgMagenta).SprintFunc()

	cBgRed    = color.New(color.BgRed, color.FgWhite, color.Bold).SprintFunc()
	cBgYellow = color.New(color.BgYellow, color.FgBlack, color.Bold).SprintFunc()
	cBgGreen  = color.New(color.BgGreen, color.FgBlack, color.Bold).SprintFunc()
)

func (p *Printer) write(format string, args ...interface{}) {
	s := fmt.Sprintf(format, args...)
	fmt.Fprint(p.out, s)
	if p.fileOut != nil {
		// Strip ANSI for file output
		fmt.Fprint(p.fileOut, stripANSI(s))
	}
}

func (p *Printer) writeln(format string, args ...interface{}) {
	p.write(format+"\n", args...)
}

func (p *Printer) hr(char string) {
	p.writeln(cDim(strings.Repeat(char, 60)))
}

func severityColor(sev string) func(...interface{}) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return cBgRed
	case "HIGH":
		return cRedPlain
	case "MEDIUM":
		return cYellow
	case "LOW":
		return cCyan
	default:
		return cDim
	}
}

// ── Banner ────────────────────────────────────────────────────────────────────

func (p *Printer) Banner() {
	if p.opts.Quiet {
		return
	}
	p.writeln("")
	p.writeln(cCyan(cBold("┌──────────────────────────────────────────────┐")))
	p.writeln(cCyan(cBold("│  🛡  shellguard  —  script security scanner   │")))
	p.writeln(cCyan(cBold("└──────────────────────────────────────────────┘")))
}

func (p *Printer) ScanHeader(source string, content []byte) {
	hash := fmt.Sprintf("%x", md5.Sum(content))
	p.writeln(cDim("  source: " + source + "  |  " + fmt.Sprintf("%d", len(content)) + " bytes  |  md5: " + hash[:12] + "…"))
}

func (p *Printer) AIHeader(model string) {
	p.writeln("")
	p.writeln(cBold("─── AI Analysis  " + cDim("("+model+")")))
}

// ── Report ────────────────────────────────────────────────────────────────────

func (p *Printer) Report(report *analyzer.Report) error {
	switch p.opts.Format {
	case "json":
		return p.reportJSON(report)
	case "sarif":
		return p.reportSARIF(report)
	case "markdown":
		return p.reportMarkdown(report)
	default:
		return p.reportPretty(report)
	}
}

func (p *Printer) reportPretty(report *analyzer.Report) error {
	p.writeln("")
	p.writeln(cBold("─── Static Analysis ─────────────────────────────────────────"))

	bySource := report.FindingsBySource()
	if len(bySource) == 0 {
		p.writeln(cGreen("  ✓  No suspicious patterns detected"))
	} else {
		sources := sortedKeys(bySource)
		for _, src := range sources {
			findings := bySource[src]
			p.writeln("")
			p.writeln("  %s  %s", cBold(cCyan("📄")), cBold(src))

			w := tabwriter.NewWriter(p.out, 0, 0, 2, ' ', 0)
			for _, f := range findings {
				sevFn := severityColor(f.Severity)
				sevLabel := sevFn(fmt.Sprintf("[%-8s]", f.Severity))
				cat := cDim("(" + tagsStr(f.Tags) + ")")
				lineRef := ""
				if f.LineNum > 0 {
					lineRef = cDim(fmt.Sprintf("line %d", f.LineNum))
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", sevLabel, cat, lineRef, f.Description)
				if f.LineText != "" {
					fmt.Fprintf(w, "  %s\t\t\t%s\n", "", cDim("  "+truncate(f.LineText, 110)))
				}
			}
			_ = w.Flush()
		}
	}

	// AI analysis block
	if report.AIResult != nil {
		p.writeln("")
		p.writeln(cBold("─── AI Assessment ───────────────────────────────────────────"))

		ar := report.AIResult
		if ar.PromptInjectionDetected {
			p.writeln("")
			p.writeln(cBgRed("  ⚠  PROMPT INJECTION DETECTED IN CONTENT  "))
			if ar.PromptInjectionDetails != "" {
				p.writeln(cRedPlain("  %s", ar.PromptInjectionDetails))
			}
		}

		if ar.Summary != "" {
			p.writeln("")
			p.writeln(cBold("  Summary:"))
			p.writeln("  %s", ar.Summary)
		}

		if len(ar.WhatItDoes) > 0 {
			p.writeln("")
			p.writeln(cBold("  What it does:"))
			for _, step := range ar.WhatItDoes {
				p.writeln("  • %s", step)
			}
		}

		if len(ar.KeyRisks) > 0 {
			p.writeln("")
			p.writeln(cBold("  Key risks:"))
			for _, r := range ar.KeyRisks {
				p.writeln("  %s %s", cRedPlain("▸"), r)
			}
		}

		intentColors := map[string]func(...interface{}) string{
			"BENIGN":           cGreen,
			"SUSPICIOUS":       cYellow,
			"LIKELY_MALICIOUS": cRedPlain,
			"MALICIOUS":        cRed,
		}
		intentFn := intentColors[ar.Intent]
		if intentFn == nil {
			intentFn = cDim
		}
		p.writeln("")
		p.writeln("  Intent: %s", intentFn(cBold(ar.Intent)))
	}

	// Activity breakdown
	p.writeln("")
	p.writeln(cBold("─── Activity Breakdown ──────────────────────────────────────"))
	cats := report.FindingsByCategory()
	if len(cats) == 0 && report.AIResult == nil {
		p.writeln(cDim("  No activity categories flagged"))
	} else {
		catNames := sortedKeys(cats)
		for _, cat := range catNames {
			fs := cats[cat]
			maxSev := fs[0].Severity
			sevFn := severityColor(maxSev)
			p.writeln("  %s %-25s %s",
				sevFn(fmt.Sprintf("[%-8s]", maxSev)),
				strings.ReplaceAll(cat, "_", " "),
				cDim(fmt.Sprintf("%d finding(s)", len(fs))),
			)
		}
	}

	// Severity summary
	counts := report.SeverityCounts()
	if len(counts) > 0 {
		p.writeln("")
		p.writeln(cBold("  Risk summary:"))
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			n := counts[sev]
			if n > 0 {
				sevFn := severityColor(sev)
				p.writeln("  %s  %d finding(s)", sevFn(fmt.Sprintf("[%-8s]", sev)), n)
			}
		}
	}

	return nil
}

// ── Verdict ───────────────────────────────────────────────────────────────────

func (p *Printer) Verdict(verdict engine.Verdict, report *analyzer.Report) {
	p.writeln("")
	p.writeln(cBold("─── Verdict ─────────────────────────────────────────────────"))

	switch verdict {
	case engine.VerdictInjection:
		p.writeln("")
		p.writeln(cBgRed("  🚨  PROMPT INJECTION DETECTED — AUTOMATIC REJECT  "))
		p.writeln(cRedPlain("  This content attempted to manipulate the security scanner."))
		p.writeln(cRedPlain("  Do NOT proceed."))

	case engine.VerdictCritical:
		p.writeln("")
		p.writeln(cBgRed("  🚨  CRITICAL RISK — NOT RECOMMENDED  "))
		p.writeln(cRedPlain("  Patterns strongly associated with malicious activity detected."))
		if report.AIResult != nil && report.AIResult.Summary != "" {
			p.writeln(cRedPlain("  AI: %s", report.AIResult.Summary))
		}

	case engine.VerdictHigh:
		p.writeln("")
		p.writeln(cBgYellow("  ⚠   HIGH RISK — REVIEW CAREFULLY  "))
		p.writeln(cYellow("  Significant risk patterns found. Verify source and intent."))

	case engine.VerdictMedium:
		p.writeln("")
		p.writeln(cYellow("  ⚡  MEDIUM RISK — PROCEED WITH CAUTION"))
		p.writeln(cYellow("  Elevated-risk patterns found. Review flagged lines above."))

	case engine.VerdictLow:
		p.writeln("")
		p.writeln(cCyan("  ℹ   LOW RISK"))
		p.writeln(cCyan("  Minor concerns. Generally okay, but review flagged items."))

	default:
		p.writeln("")
		p.writeln(cBgGreen("  ✓   NO SIGNIFICANT RISKS DETECTED  "))
		if report.AIResult != nil && report.AIResult.Summary != "" {
			p.writeln(cGreen("  AI: %s", report.AIResult.Summary))
		}
	}
}

// ── Prompt ────────────────────────────────────────────────────────────────────

func (p *Printer) Prompt(verdict engine.Verdict) bool {
	p.writeln("")
	p.writeln(cBold("─── Decision ────────────────────────────────────────────────"))

	var promptStr string
	var defaultYes bool

	switch verdict {
	case engine.VerdictInjection, engine.VerdictCritical:
		p.writeln(cRedPlain("  ⚠  Strongly recommended: DO NOT proceed"))
		promptStr = "  Proceed anyway? [y/N]: "
		defaultYes = false
	case engine.VerdictHigh:
		p.writeln(cYellow("  Review the findings above carefully before deciding."))
		promptStr = "  Proceed? [y/N]: "
		defaultYes = false
	default:
		promptStr = "  Proceed? [Y/n]: "
		defaultYes = true
	}

	fmt.Fprint(os.Stderr, promptStr)
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if answer == "" {
			return defaultYes
		}
		return answer == "y" || answer == "yes"
	}
	return false
}

func (p *Printer) Approved() {
	p.writeln(cGreen("\n  ✓  Proceeding.\n"))
}

func (p *Printer) Rejected() {
	p.writeln(cRedPlain("\n  ✗  Aborted. Script was NOT executed.\n"))
}

// ── JSON output ───────────────────────────────────────────────────────────────

type jsonReport struct {
	Timestamp string           `json:"timestamp"`
	Source    string           `json:"source"`
	Verdict   string           `json:"verdict"`
	Findings  []engine.Finding `json:"findings"`
	AI        *ai.Result       `json:"ai_analysis,omitempty"`
	Counts    map[string]int   `json:"severity_counts"`
}

func (p *Printer) reportJSON(report *analyzer.Report) error {
	out := jsonReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Source:    report.Source,
		Findings:  report.Findings,
		AI:        report.AIResult,
		Counts:    report.SeverityCounts(),
	}
	if report.Findings == nil {
		out.Findings = []engine.Finding{}
	}

	var w io.Writer = os.Stdout
	if p.fileOut != nil {
		w = io.MultiWriter(os.Stdout, p.fileOut)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// ── SARIF output ──────────────────────────────────────────────────────────────

func (p *Printer) reportSARIF(report *analyzer.Report) error {
	type sarifLocation struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *struct {
				StartLine int `json:"startLine,omitempty"`
			} `json:"region,omitempty"`
		} `json:"physicalLocation"`
	}

	type sarifResult struct {
		RuleID  string `json:"ruleId"`
		Level   string `json:"level"`
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations []sarifLocation `json:"locations"`
	}

	var results []sarifResult
	for _, f := range report.Findings {
		level := "warning"
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL", "HIGH":
			level = "error"
		case "LOW", "INFO":
			level = "note"
		}

		var locs []sarifLocation
		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.Source
		if f.LineNum > 0 {
			loc.PhysicalLocation.Region = &struct {
				StartLine int `json:"startLine,omitempty"`
			}{StartLine: f.LineNum}
		}
		locs = append(locs, loc)

		r := sarifResult{
			RuleID:    f.RuleID,
			Level:     level,
			Locations: locs,
		}
		r.Message.Text = f.Description
		results = append(results, r)
	}

	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "shellguard",
						"informationUri": "https://github.com/fvckgrimm/shellguard",
					},
				},
				"results": results,
			},
		},
	}

	var w io.Writer = os.Stdout
	if p.fileOut != nil {
		w = io.MultiWriter(os.Stdout, p.fileOut)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

// ── Markdown output ───────────────────────────────────────────────────────────

func (p *Printer) reportMarkdown(report *analyzer.Report) error {
	var sb strings.Builder

	sb.WriteString("# shellguard Security Report\n\n")
	sb.WriteString(fmt.Sprintf("**Source:** `%s`  \n", report.Source))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n\n", time.Now().UTC().Format(time.RFC3339)))

	verdict := report.Verdict()
	verdictEmoji := map[engine.Verdict]string{
		engine.VerdictClean:     "✅",
		engine.VerdictInfo:      "ℹ️",
		engine.VerdictLow:       "🔵",
		engine.VerdictMedium:    "⚠️",
		engine.VerdictHigh:      "🔴",
		engine.VerdictCritical:  "🚨",
		engine.VerdictInjection: "💉",
	}
	sb.WriteString(fmt.Sprintf("## Verdict: %s %s\n\n", verdictEmoji[verdict], verdict.String()))

	if len(report.Findings) == 0 {
		sb.WriteString("No suspicious patterns detected.\n\n")
	} else {
		sb.WriteString("## Findings\n\n")
		sb.WriteString("| Severity | Rule | Line | Description | Source |\n")
		sb.WriteString("|----------|------|------|-------------|--------|\n")
		for _, f := range report.Findings {
			sb.WriteString(fmt.Sprintf("| **%s** | `%s` | %d | %s | `%s` |\n",
				f.Severity, f.RuleID, f.LineNum, f.Description, f.Source))
		}
		sb.WriteString("\n")
	}

	if report.AIResult != nil {
		ar := report.AIResult
		sb.WriteString("## AI Analysis\n\n")
		if ar.PromptInjectionDetected {
			sb.WriteString("⚠️ **PROMPT INJECTION DETECTED**\n\n")
			if ar.PromptInjectionDetails != "" {
				sb.WriteString("> " + ar.PromptInjectionDetails + "\n\n")
			}
		}
		sb.WriteString(fmt.Sprintf("**Summary:** %s\n\n", ar.Summary))
		sb.WriteString(fmt.Sprintf("**Intent:** %s\n\n", ar.Intent))
		if len(ar.WhatItDoes) > 0 {
			sb.WriteString("**What it does:**\n\n")
			for _, s := range ar.WhatItDoes {
				sb.WriteString("- " + s + "\n")
			}
			sb.WriteString("\n")
		}
		if len(ar.KeyRisks) > 0 {
			sb.WriteString("**Key risks:**\n\n")
			for _, r := range ar.KeyRisks {
				sb.WriteString("- " + r + "\n")
			}
			sb.WriteString("\n")
		}
	}

	var w io.Writer = os.Stdout
	if p.fileOut != nil {
		w = io.MultiWriter(os.Stdout, p.fileOut)
	}
	_, err := fmt.Fprint(w, sb.String())
	return err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func tagsStr(tags []string) string {
	if len(tags) == 0 {
		return ""
	}
	return strings.Join(tags, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}
