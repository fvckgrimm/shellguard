package resolver

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fvckgrimm/shellguard/internal/analyzer"
)

// ── Patterns: local file references ──────────────────────────────────────────

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

// ── Patterns: remote script execution chains ──────────────────────────────────
// Matches: curl <flags> <url> | bash
//          wget <flags> <url> | bash/sh
//          curl <url> | bash -s <args>
//          curl <url> > /tmp/x && bash /tmp/x  (download-then-exec)

var remoteExecPatterns = []*regexp.Regexp{
	// curl ... URL | bash/sh
	regexp.MustCompile(`(?i)curl\s+[^\n]*?(https?://[^\s'"&|;]+)\s*\|\s*(?:sudo\s+)?(?:ba)?sh`),
	// wget -qO- URL | bash/sh
	regexp.MustCompile(`(?i)wget\s+[^\n]*?(https?://[^\s'"&|;]+)\s*\|\s*(?:sudo\s+)?(?:ba)?sh`),
	// curl ... URL | bash -s ...
	regexp.MustCompile(`(?i)curl\s+[^\n]*?(https?://[^\s'"&|;]+)\s*\|\s*(?:sudo\s+)?(?:ba)?sh\s+-s`),
	// curl -fsSL URL -o /tmp/x
	regexp.MustCompile(`(?i)curl\s+[^\n]*?(https?://[^\s'"&|;]+)\s+-o\s+\S+`),
	// wget URL -O /tmp/x
	regexp.MustCompile(`(?i)wget\s+[^\n]*?(https?://[^\s'"&|;]+)\s+-O\s+\S+`),
}

// httpClient with a reasonable timeout
var httpClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// FetchOptions controls remote fetch behaviour
type FetchOptions struct {
	NoFetch    bool     // disable remote fetching entirely
	AllowHosts []string // if non-empty, only fetch from these hosts
	BlockHosts []string // never fetch from these hosts
}

// ScanRefs finds and scans all referenced content — local files AND remote scripts
func ScanRefs(content, source string, opts analyzer.ScanOptions, maxDepth int) []*analyzer.Report {
	visited := map[string]bool{source: true}
	fetched := map[string]bool{}
	contentSeen := map[uint64]bool{contentHash(content): true} // dedup by content
	return scanRefsRecurse(content, opts, maxDepth, 0, visited, fetched, contentSeen, FetchOptions{})
}

// ScanRefsWithOptions accepts fetch configuration
func ScanRefsWithOptions(content, source string, opts analyzer.ScanOptions, maxDepth int, fetchOpts FetchOptions) []*analyzer.Report {
	visited := map[string]bool{source: true}
	fetched := map[string]bool{}
	contentSeen := map[uint64]bool{contentHash(content): true}
	return scanRefsRecurse(content, opts, maxDepth, 0, visited, fetched, contentSeen, fetchOpts)
}

func scanRefsRecurse(
	content string,
	opts analyzer.ScanOptions,
	maxDepth, depth int,
	visited map[string]bool,
	fetched map[string]bool,
	contentSeen map[uint64]bool,
	fetchOpts FetchOptions,
) []*analyzer.Report {
	if depth >= maxDepth {
		return nil
	}

	var reports []*analyzer.Report

	// ── Local file refs ───────────────────────────────────────────────────────
	for _, ref := range extractLocalRefs(content, opts.WorkDir) {
		if visited[ref] {
			continue
		}
		visited[ref] = true

		refContent, err := os.ReadFile(ref)
		if err != nil {
			continue
		}

		h := contentHash(string(refContent))
		if contentSeen[h] {
			fmt.Fprintf(os.Stderr, "  ↳ skipping (duplicate content): %s\n", ref)
			continue
		}
		contentSeen[h] = true

		subOpts := opts
		subOpts.Content = string(refContent)
		subOpts.Source = ref
		subOpts.WorkDir = filepath.Dir(ref)

		report, err := analyzer.Scan(subOpts)
		if err != nil {
			continue
		}

		subReports := scanRefsRecurse(string(refContent), subOpts, maxDepth, depth+1, visited, fetched, contentSeen, fetchOpts)
		for _, sr := range subReports {
			report.Merge(sr)
		}

		reports = append(reports, report)
	}

	// ── Remote URL chains ─────────────────────────────────────────────────────
	if !fetchOpts.NoFetch {
		for _, remoteURL := range extractRemoteURLs(content) {
			urlKey := strings.ToLower(remoteURL)
			if fetched[urlKey] {
				continue
			}

			if !shouldFetch(remoteURL, fetchOpts) {
				fmt.Fprintf(os.Stderr, "  ↳ skipping (blocked host): %s\n", remoteURL)
				continue
			}

			fetched[urlKey] = true
			fmt.Fprintf(os.Stderr, "  ↳ fetching remote script: %s\n", remoteURL)

			remoteContent, err := fetchURL(remoteURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ↳ fetch failed: %s: %v\n", remoteURL, err)
				continue
			}

			// Dedup by content hash — catches redirects serving the same file under a different URL
			h := contentHash(remoteContent)
			if contentSeen[h] {
				fmt.Fprintf(os.Stderr, "  ↳ skipping (duplicate content): %s\n", remoteURL)
				continue
			}
			contentSeen[h] = true

			subOpts := opts
			subOpts.Content = remoteContent
			subOpts.Source = remoteURL
			subOpts.WorkDir = ""

			report, err := analyzer.Scan(subOpts)
			if err != nil {
				continue
			}

			subReports := scanRefsRecurse(remoteContent, subOpts, maxDepth, depth+1, visited, fetched, contentSeen, fetchOpts)
			for _, sr := range subReports {
				report.Merge(sr)
			}

			reports = append(reports, report)
		}
	}

	return reports
}

// extractLocalRefs pulls local file paths from content
func extractLocalRefs(content, workDir string) []string {
	refSet := map[string]bool{}

	for _, re := range fileRefPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			ref := strings.TrimSpace(m[1])
			if ref == "" || strings.HasPrefix(ref, "-") || strings.HasPrefix(ref, "http") {
				continue
			}
			// Skip shell variables — can't resolve statically
			if strings.ContainsAny(ref, "${}") {
				continue
			}
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

// extractRemoteURLs pulls remote script URLs from curl|bash / wget|bash patterns
func extractRemoteURLs(content string) []string {
	urlSet := map[string]bool{}

	for _, re := range remoteExecPatterns {
		matches := re.FindAllStringSubmatch(content, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			rawURL := strings.TrimSpace(m[1])
			rawURL = strings.TrimRight(rawURL, `"';|&`)
			if rawURL == "" {
				continue
			}
			if u, err := url.ParseRequestURI(rawURL); err == nil && u.Host != "" {
				urlSet[rawURL] = true
			}
		}
	}

	urls := make([]string, 0, len(urlSet))
	for u := range urlSet {
		urls = append(urls, u)
	}
	return urls
}

// fetchURL retrieves a remote script's content
func fetchURL(rawURL string) (string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "shellguard-scanner/1.0 (security scanner)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Cap at 5MB — scripts, not binaries
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// shouldFetch checks allow/block lists
func shouldFetch(rawURL string, opts FetchOptions) bool {
	u, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())

	for _, blocked := range opts.BlockHosts {
		if strings.HasSuffix(host, strings.ToLower(blocked)) {
			return false
		}
	}

	if len(opts.AllowHosts) > 0 {
		for _, allowed := range opts.AllowHosts {
			if strings.HasSuffix(host, strings.ToLower(allowed)) {
				return true
			}
		}
		return false
	}

	return true
}

// ExtractRemoteURLs is exported for use in reporting
func ExtractRemoteURLs(content string) []string {
	return extractRemoteURLs(content)
}

// contentHash returns a fast FNV-1a hash of content for deduplication
func contentHash(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
