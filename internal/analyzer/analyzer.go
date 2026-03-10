package analyzer

import (
	"sort"
	"strings"

	"github.com/fvckgrimm/shellguard/internal/ai"
	"github.com/fvckgrimm/shellguard/internal/engine"
)

type ScanOptions struct {
	Content   string
	Source    string
	MaxDepth  int
	NoRecurse bool
	Engine    *engine.Engine
	WorkDir   string
}

type Report struct {
	Source   string
	Findings []engine.Finding
	AIResult *ai.Result
	SubScans []*Report // referenced files
}

func Scan(opts ScanOptions) (*Report, error) {
	report := &Report{Source: opts.Source}

	if opts.Engine == nil {
		return report, nil
	}

	report.Findings = opts.Engine.Match(opts.Content, opts.Source)
	return report, nil
}

func (r *Report) Merge(other *Report) {
	r.Findings = append(r.Findings, other.Findings...)
	r.SubScans = append(r.SubScans, other)
	// Re-sort
	sort.Slice(r.Findings, func(i, j int) bool {
		si := engine.ParseSeverity(r.Findings[i].Severity)
		sj := engine.ParseSeverity(r.Findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return r.Findings[i].Source < r.Findings[j].Source
	})
}

func (r *Report) Verdict() engine.Verdict {
	// Check for prompt injection tag first — always escalates
	for _, f := range r.Findings {
		for _, t := range f.Tags {
			if strings.EqualFold(t, "prompt_injection") {
				return engine.VerdictInjection
			}
		}
	}

	if r.AIResult != nil && r.AIResult.PromptInjectionDetected {
		return engine.VerdictInjection
	}

	maxSev := engine.SeverityInfo
	for _, f := range r.Findings {
		s := engine.ParseSeverity(f.Severity)
		if s > maxSev {
			maxSev = s
		}
	}

	// AI result can escalate
	if r.AIResult != nil {
		aiSev := engine.ParseSeverity(r.AIResult.OverallRisk)
		if aiSev > maxSev {
			maxSev = aiSev
		}
	}

	switch maxSev {
	case engine.SeverityCritical:
		return engine.VerdictCritical
	case engine.SeverityHigh:
		return engine.VerdictHigh
	case engine.SeverityMedium:
		return engine.VerdictMedium
	case engine.SeverityLow:
		return engine.VerdictLow
	default:
		if len(r.Findings) == 0 {
			return engine.VerdictClean
		}
		return engine.VerdictInfo
	}
}

// FindingsByCategory groups findings by their first tag
func (r *Report) FindingsByCategory() map[string][]engine.Finding {
	cats := map[string][]engine.Finding{}
	for _, f := range r.Findings {
		cat := "other"
		if len(f.Tags) > 0 {
			cat = f.Tags[0]
		}
		cats[cat] = append(cats[cat], f)
	}
	return cats
}

// FindingsBySource groups findings by source file
func (r *Report) FindingsBySource() map[string][]engine.Finding {
	sources := map[string][]engine.Finding{}
	for _, f := range r.Findings {
		sources[f.Source] = append(sources[f.Source], f)
	}
	return sources
}

// SeverityCounts returns count per severity level
func (r *Report) SeverityCounts() map[string]int {
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	return counts
}
