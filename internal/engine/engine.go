package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── Severity ─────────────────────────────────────────────────────────────────

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// ── Verdict ───────────────────────────────────────────────────────────────────

type Verdict int

const (
	VerdictClean     Verdict = iota // no findings
	VerdictInfo                     // info-only findings
	VerdictLow                      // only low severity
	VerdictMedium                   // medium findings
	VerdictHigh                     // high findings
	VerdictCritical                 // critical findings
	VerdictInjection                // prompt injection detected
)

func (v Verdict) String() string {
	switch v {
	case VerdictClean:
		return "CLEAN"
	case VerdictInfo:
		return "INFO"
	case VerdictLow:
		return "LOW"
	case VerdictMedium:
		return "MEDIUM"
	case VerdictHigh:
		return "HIGH"
	case VerdictCritical:
		return "CRITICAL"
	case VerdictInjection:
		return "INJECTION"
	default:
		return "UNKNOWN"
	}
}

// ── Rule Pack YAML schema ─────────────────────────────────────────────────────

type RulePackFile struct {
	ID          string     `yaml:"id"`
	Name        string     `yaml:"name"`
	Version     string     `yaml:"version"`
	Description string     `yaml:"description"`
	Author      string     `yaml:"author"`
	Tags        []string   `yaml:"tags"`
	Rules       []RuleSpec `yaml:"rules"`
}

type RuleSpec struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
	Tags        []string    `yaml:"tags"`
	Match       MatchSpec   `yaml:"match"`
	Context     ContextSpec `yaml:"context"`
	Remediation string      `yaml:"remediation"`
	References  []string    `yaml:"references"`
	Enabled     *bool       `yaml:"enabled"` // nil = true
}

type MatchSpec struct {
	Mode     string   `yaml:"mode"`     // regex, multi_regex, keyword, keywords_any
	Pattern  string   `yaml:"pattern"`  // for regex
	Patterns []string `yaml:"patterns"` // for multi_regex
	Keywords []string `yaml:"keywords"` // for keyword modes
	Logic    string   `yaml:"logic"`    // all | any (for multi_regex)
	Flags    []string `yaml:"flags"`    // case_insensitive, multiline, dotall
	Negate   bool     `yaml:"negate"`
}

type ContextSpec struct {
	RequireAny []string `yaml:"require_any"`
	RequireAll []string `yaml:"require_all"`
	ExcludeAny []string `yaml:"exclude_any"`
}

// ── Compiled Rule ─────────────────────────────────────────────────────────────

type Rule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	Tags        []string
	PackID      string
	Remediation string
	References  []string

	compiled *compiledMatcher
}

type compiledMatcher struct {
	spec      MatchSpec
	regexps   []*regexp.Regexp
	ctxReqs   []*regexp.Regexp
	ctxReqAll []*regexp.Regexp
	ctxExcl   []*regexp.Regexp
}

func (r *Rule) Match(content string) (bool, []int) {
	if r.compiled == nil {
		return false, nil
	}
	return r.compiled.match(content)
}

func (cm *compiledMatcher) match(content string) (bool, []int) {
	var matched bool
	var lines []int

	switch cm.spec.Mode {
	case "regex":
		if len(cm.regexps) == 0 {
			return false, nil
		}
		re := cm.regexps[0]
		lineNum := 1
		for _, line := range strings.Split(content, "\n") {
			if re.MatchString(line) {
				lines = append(lines, lineNum)
				matched = true
			}
			lineNum++
		}

	case "multi_regex":
		logic := strings.ToLower(cm.spec.Logic)
		if logic == "" {
			logic = "any"
		}
		allMatched := true
		anyMatched := false
		matchLines := map[int]bool{}

		for _, re := range cm.regexps {
			reMatched := false
			lineNum := 1
			for _, line := range strings.Split(content, "\n") {
				if re.MatchString(line) {
					matchLines[lineNum] = true
					reMatched = true
					anyMatched = true
				}
				lineNum++
			}
			if !reMatched {
				allMatched = false
			}
		}

		switch logic {
		case "all":
			matched = allMatched
		default:
			matched = anyMatched
		}
		for l := range matchLines {
			lines = append(lines, l)
		}
		sort.Ints(lines)

	case "keyword", "keywords_all":
		allMatched := true
		lineNum := 1
		for _, line := range strings.Split(content, "\n") {
			lower := strings.ToLower(line)
			for _, kw := range cm.spec.Keywords {
				if strings.Contains(lower, strings.ToLower(kw)) {
					lines = append(lines, lineNum)
					matched = true
				}
			}
			lineNum++
		}
		if cm.spec.Mode == "keywords_all" {
			// All keywords must appear somewhere
			for _, kw := range cm.spec.Keywords {
				if !strings.Contains(strings.ToLower(content), strings.ToLower(kw)) {
					allMatched = false
					break
				}
			}
			matched = allMatched
		}

	case "keywords_any":
		lineNum := 1
		for _, line := range strings.Split(content, "\n") {
			lower := strings.ToLower(line)
			for _, kw := range cm.spec.Keywords {
				if strings.Contains(lower, strings.ToLower(kw)) {
					lines = append(lines, lineNum)
					matched = true
				}
			}
			lineNum++
		}
	}

	if cm.spec.Negate {
		matched = !matched
	}

	if !matched {
		return false, nil
	}

	// Context checks
	for _, re := range cm.ctxReqs {
		if !re.MatchString(content) {
			return false, nil
		}
	}
	for _, re := range cm.ctxReqAll {
		if !re.MatchString(content) {
			return false, nil
		}
	}
	for _, re := range cm.ctxExcl {
		if re.MatchString(content) {
			return false, nil
		}
	}

	return true, lines
}

// ── Pack (loaded) ─────────────────────────────────────────────────────────────

type Pack struct {
	ID          string
	Name        string
	Version     string
	Description string
	Author      string
	Tags        []string
	Rules       []Rule
	SourceFile  string
}

// ── Engine ────────────────────────────────────────────────────────────────────

type Options struct {
	RulePackDirs []string
	EnabledPacks []string
	Tags         []string
	ExcludeTags  []string
	MinSeverity  Severity
}

type Engine struct {
	packs []Pack
	rules []Rule
	opts  Options
}

func New(opts Options) (*Engine, error) {
	eng := &Engine{opts: opts}
	if err := eng.load(); err != nil {
		return nil, err
	}
	return eng, nil
}

func (e *Engine) load() error {
	for _, dir := range e.opts.RulePackDirs {
		if err := e.loadDir(dir); err != nil {
			// Don't fail on missing dirs
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("loading rules from %s: %w", dir, err)
		}
	}
	e.buildRuleIndex()
	return nil
}

func (e *Engine) loadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			// Recurse one level
			sub := filepath.Join(dir, entry.Name())
			_ = e.loadDir(sub)
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		pack, err := LoadPackFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping invalid rule pack %s: %v\n", name, err)
			continue
		}
		// Filter by enabled packs
		if len(e.opts.EnabledPacks) > 0 && !contains(e.opts.EnabledPacks, pack.ID) {
			continue
		}
		e.packs = append(e.packs, *pack)
	}
	return nil
}

func (e *Engine) buildRuleIndex() {
	for _, pack := range e.packs {
		for _, rule := range pack.Rules {
			// Tag filter
			if len(e.opts.Tags) > 0 && !ruleMatchesTags(rule, e.opts.Tags) {
				continue
			}
			if len(e.opts.ExcludeTags) > 0 && ruleMatchesTags(rule, e.opts.ExcludeTags) {
				continue
			}
			// Severity filter
			if ParseSeverity(rule.Severity) < e.opts.MinSeverity {
				continue
			}
			e.rules = append(e.rules, rule)
		}
	}
}

// Match runs all rules against content and returns findings
func (e *Engine) Match(content, source string) []Finding {
	var findings []Finding
	seen := map[string]bool{} // deduplicate rule+line

	for _, rule := range e.rules {
		matched, matchLines := rule.Match(content)
		if !matched {
			continue
		}
		lines := splitLines(content)
		for _, lineNum := range matchLines {
			key := fmt.Sprintf("%s:%d", rule.ID, lineNum)
			if seen[key] {
				continue
			}
			seen[key] = true

			lineText := ""
			if lineNum > 0 && lineNum <= len(lines) {
				lineText = strings.TrimSpace(lines[lineNum-1])
			}

			findings = append(findings, Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Tags:        rule.Tags,
				PackID:      rule.PackID,
				LineNum:     lineNum,
				LineText:    lineText,
				Source:      source,
				Remediation: rule.Remediation,
				References:  rule.References,
			})
		}

		// If no specific lines (e.g. negate or full-content match), still report
		if len(matchLines) == 0 {
			findings = append(findings, Finding{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Description: rule.Description,
				Severity:    rule.Severity,
				Tags:        rule.Tags,
				PackID:      rule.PackID,
				Source:      source,
				Remediation: rule.Remediation,
				References:  rule.References,
			})
		}
	}

	// Sort: critical first
	sort.Slice(findings, func(i, j int) bool {
		si := ParseSeverity(findings[i].Severity)
		sj := ParseSeverity(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return findings[i].LineNum < findings[j].LineNum
	})

	return findings
}

func (e *Engine) LoadedPacks() []Pack { return e.packs }
func (e *Engine) Rules() []Rule       { return e.rules }

func (e *Engine) AllTags() []string {
	tagSet := map[string]bool{}
	for _, r := range e.rules {
		for _, t := range r.Tags {
			tagSet[t] = true
		}
	}
	var tags []string
	for t := range tagSet {
		tags = append(tags, t)
	}
	sort.Strings(tags)
	return tags
}

func (e *Engine) CountByTag(tag string) int {
	n := 0
	for _, r := range e.rules {
		for _, t := range r.Tags {
			if t == tag {
				n++
				break
			}
		}
	}
	return n
}

// ── Finding ───────────────────────────────────────────────────────────────────

type Finding struct {
	RuleID      string   `json:"rule_id"`
	RuleName    string   `json:"rule_name"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags"`
	PackID      string   `json:"pack_id"`
	LineNum     int      `json:"line_num,omitempty"`
	LineText    string   `json:"line_text,omitempty"`
	Source      string   `json:"source"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// ── Load ──────────────────────────────────────────────────────────────────────

func LoadPackFile(path string) (*Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pf RulePackFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("YAML parse error: %w", err)
	}

	if pf.ID == "" {
		return nil, fmt.Errorf("rule pack missing required field: id")
	}

	pack := &Pack{
		ID:          pf.ID,
		Name:        pf.Name,
		Version:     pf.Version,
		Description: pf.Description,
		Author:      pf.Author,
		Tags:        pf.Tags,
		SourceFile:  path,
	}

	for _, spec := range pf.Rules {
		if spec.Enabled != nil && !*spec.Enabled {
			continue
		}

		compiled, err := compileRule(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping rule %s in %s: %v\n", spec.ID, pf.ID, err)
			continue
		}

		pack.Rules = append(pack.Rules, Rule{
			ID:          spec.ID,
			Name:        spec.Name,
			Description: spec.Description,
			Severity:    spec.Severity,
			Tags:        spec.Tags,
			PackID:      pf.ID,
			Remediation: spec.Remediation,
			References:  spec.References,
			compiled:    compiled,
		})
	}

	return pack, nil
}

func compileRule(spec RuleSpec) (*compiledMatcher, error) {
	cm := &compiledMatcher{spec: spec.Match}

	flags := ""
	for _, f := range spec.Match.Flags {
		switch strings.ToLower(f) {
		case "case_insensitive":
			flags += "(?i)"
		case "multiline":
			flags += "(?m)"
		case "dotall":
			flags += "(?s)"
		}
	}

	switch spec.Match.Mode {
	case "regex":
		if spec.Match.Pattern == "" {
			return nil, fmt.Errorf("regex mode requires 'pattern'")
		}
		re, err := regexp.Compile(flags + spec.Match.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", spec.Match.Pattern, err)
		}
		cm.regexps = []*regexp.Regexp{re}

	case "multi_regex":
		if len(spec.Match.Patterns) == 0 {
			return nil, fmt.Errorf("multi_regex mode requires 'patterns'")
		}
		for _, p := range spec.Match.Patterns {
			re, err := regexp.Compile(flags + p)
			if err != nil {
				return nil, fmt.Errorf("invalid regex %q: %w", p, err)
			}
			cm.regexps = append(cm.regexps, re)
		}

	case "keyword", "keywords_any", "keywords_all":
		if len(spec.Match.Keywords) == 0 {
			return nil, fmt.Errorf("keyword mode requires 'keywords'")
		}

	case "":
		return nil, fmt.Errorf("match.mode is required")

	default:
		return nil, fmt.Errorf("unknown match mode %q (valid: regex, multi_regex, keyword, keywords_any, keywords_all)", spec.Match.Mode)
	}

	// Compile context patterns
	for _, p := range spec.Context.RequireAny {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid context pattern %q: %w", p, err)
		}
		cm.ctxReqs = append(cm.ctxReqs, re)
	}
	for _, p := range spec.Context.RequireAll {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid context pattern %q: %w", p, err)
		}
		cm.ctxReqAll = append(cm.ctxReqAll, re)
	}
	for _, p := range spec.Context.ExcludeAny {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			return nil, fmt.Errorf("invalid context pattern %q: %w", p, err)
		}
		cm.ctxExcl = append(cm.ctxExcl, re)
	}

	return cm, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func ruleMatchesTags(rule Rule, tags []string) bool {
	for _, want := range tags {
		for _, have := range rule.Tags {
			if strings.EqualFold(have, want) {
				return true
			}
		}
	}
	return false
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}
