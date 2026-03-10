package resolver

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fvckgrimm/shellguard/internal/analyzer"
)

// fileRefPatterns extracts referenced script/config paths from content
var fileRefPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*source\s+['"]?([^\s'";&|]+)['"]?`),
	regexp.MustCompile(`(?m)^\s*\.\s+['"]?([^\s'";&|]+\.sh)['"]?`),
	regexp.MustCompile(`(?m)bash\s+['"]?([^\s'";&|<>]+\.sh)['"]?`),
	regexp.MustCompile(`(?m)\bsh\s+['"]?([^\s'";&|<>]+\.sh)['"]?`),
	regexp.MustCompile(`(?m)python3?\s+['"]?([^\s'";&|<>]+\.py)['"]?`),
	regexp.MustCompile(`(?m)perl\s+['"]?([^\s'";&|<>]+\.pl)['"]?`),
	regexp.MustCompile(`(?m)ruby\s+['"]?([^\s'";&|<>]+\.rb)['"]?`),
	regexp.MustCompile(`(?m)<\s*['"]?([^\s'";&|<>]+\.(?:sh|py|pl|rb|yaml|yml|json|conf|cfg|env))['"]?`),
}

// ScanRefs finds referenced files in content and scans them recursively
func ScanRefs(content, source string, opts analyzer.ScanOptions, maxDepth int) []*analyzer.Report {
	visited := map[string]bool{source: true}
	return scanRefsRecurse(content, opts, maxDepth, 0, visited)
}

func scanRefsRecurse(content string, opts analyzer.ScanOptions, maxDepth, depth int, visited map[string]bool) []*analyzer.Report {
	if depth >= maxDepth {
		return nil
	}

	refs := extractRefs(content, opts.WorkDir)
	var reports []*analyzer.Report

	for _, ref := range refs {
		if visited[ref] {
			continue
		}
		visited[ref] = true

		refContent, err := os.ReadFile(ref)
		if err != nil {
			continue
		}

		subOpts := opts
		subOpts.Content = string(refContent)
		subOpts.Source = ref
		subOpts.WorkDir = filepath.Dir(ref)

		report, err := analyzer.Scan(subOpts)
		if err != nil {
			continue
		}

		// Recurse
		subRefs := scanRefsRecurse(string(refContent), subOpts, maxDepth, depth+1, visited)
		for _, sr := range subRefs {
			report.Merge(sr)
		}

		reports = append(reports, report)
	}

	return reports
}

func extractRefs(content, workDir string) []string {
	refSet := map[string]bool{}

	for _, re := range fileRefPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ref := strings.TrimSpace(m[1])
			if ref == "" || strings.HasPrefix(ref, "-") {
				continue
			}
			// Resolve relative paths
			if !filepath.IsAbs(ref) {
				ref = filepath.Join(workDir, ref)
			}
			ref = filepath.Clean(ref)
			refSet[ref] = true
		}
	}

	refs := make([]string, 0, len(refSet))
	for r := range refSet {
		refs = append(refs, r)
	}
	return refs
}
