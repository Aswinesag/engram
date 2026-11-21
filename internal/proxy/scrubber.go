package proxy

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	DefaultEntropyThreshold   = 4.5
	DefaultMinEntropyTokenLen = 24
	DefaultMinKnownSecretLen  = 8
)

// Finding describes a single detected secret span without exposing the raw secret value.
type Finding struct {
	Rule         string  `json:"rule"`
	MatchPreview string  `json:"match_preview"`
	Start        int     `json:"start"`
	End          int     `json:"end"`
	Entropy      float64 `json:"entropy,omitempty"`
}

// ScrubResult holds the outcome of scanning and redacting a text payload.
type ScrubResult struct {
	Clean    bool      `json:"clean"`
	Redacted string    `json:"redacted"`
	Findings []Finding `json:"findings,omitempty"`
}

// ScrubberConfig tunes regex, entropy, and known-.env secret detection.
type ScrubberConfig struct {
	EntropyThreshold   float64
	MinEntropyTokenLen int
	AdditionalSecrets  []string
	DisableEntropy     bool
}

type regexRule struct {
	name       string
	re         *regexp.Regexp
	valueGroup int // 0 = full match, >0 = capture group index containing the secret
	filter     func(fullMatch, value string) bool
}

// Scrubber scans outbound HTTP payloads and LLM prompts using high-precision
// regex detectors, exact .env secret matching, and Shannon entropy analysis.
type Scrubber struct {
	entropyThreshold   float64
	minEntropyTokenLen int
	disableEntropy     bool
	knownSecrets       []string
	rules              []regexRule
}

var (
	defaultRegexRules = []regexRule{
		{
			name: "ssh_private_key",
			re:   regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		},
		{
			name: "ssh_private_key",
			re:   regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
		},
		{
			name: "anthropic_api_key",
			re:   regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
		},
		{
			name: "openai_api_key",
			re:   regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b`),
		},
		{
			name: "github_token",
			re:   regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b`),
		},
		{
			name: "github_token",
			re:   regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`),
		},
		{
			name: "aws_access_key",
			re:   regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		},
		{
			name: "google_api_key",
			re:   regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		},
		{
			name: "slack_token",
			re:   regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
		},
		{
			name: "stripe_key",
			re:   regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b`),
		},
		{
			name: "jwt",
			re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		},
		{
			name:       "bearer_token",
			re:         regexp.MustCompile(`(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/=-]{20,})`),
			valueGroup: 1,
			filter: func(_, val string) bool {
				return !isPlaceholderOrReference(val)
			},
		},
		{
			name:       "env_secret",
			re:         regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:API_KEY|SECRET_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY|CLIENT_SECRET|DATABASE_URL|DB_PASSWORD|SIGNING_KEY))\s*(?:=|:)\s*["']?([^\s"'` + "`" + `,;}{]{12,})["']?`),
			valueGroup: 2,
			filter: func(_, val string) bool {
				return !isPlaceholderOrReference(val)
			},
		},
	}

	// Candidate token pattern for Shannon high-entropy scanning.
	entropyTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)

	// Common file extensions to suppress false positives on filesystem paths or URLs.
	codeFileExtRe = regexp.MustCompile(`(?i)\.(?:go|py|ts|tsx|js|jsx|json|toml|ya?ml|md|sql|txt|log|sh|ps1|exe|dll|so|dylib|html|css|svg|png|jpg|pdf|zip|gz|tar)$`)

	// Redacted placeholder marker so repeated Scrub calls remain idempotent.
	redactedSpanRe = regexp.MustCompile(`\[REDACTED:[a-z0-9_]+\]`)
)

// NewScrubber constructs a secret scanner and redactor with safe defaults.
func NewScrubber(cfg ScrubberConfig) *Scrubber {
	threshold := cfg.EntropyThreshold
	if threshold <= 0 {
		threshold = DefaultEntropyThreshold
	}
	minLen := cfg.MinEntropyTokenLen
	if minLen <= 0 {
		minLen = DefaultMinEntropyTokenLen
	}

	seen := make(map[string]struct{}, len(cfg.AdditionalSecrets))
	var known []string
	for _, s := range cfg.AdditionalSecrets {
		s = strings.TrimSpace(s)
		if len(s) < DefaultMinKnownSecretLen || isBenignEnvValue(s) {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		known = append(known, s)
	}
	// Longest first so exact-value matching prefers full secrets over substrings.
	sort.Slice(known, func(i, j int) bool {
		if len(known[i]) != len(known[j]) {
			return len(known[i]) > len(known[j])
		}
		return known[i] < known[j]
	})

	return &Scrubber{
		entropyThreshold:   threshold,
		minEntropyTokenLen: minLen,
		disableEntropy:     cfg.DisableEntropy,
		knownSecrets:       known,
		rules:              defaultRegexRules,
	}
}

// LoadDotEnvSecrets parses a .env file and extracts non-trivial secret values
// for deterministic exact-match blocking without false positives on ports/booleans.
func LoadDotEnvSecrets(envFilePath string) ([]string, error) {
	f, err := os.Open(envFilePath)
	if err != nil {
		return nil, fmt.Errorf("proxy: open dotenv file %q: %w", envFilePath, err)
	}
	defer f.Close()

	var secrets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = stripDotEnvQuotes(strings.TrimSpace(val))
		if key == "" || len(val) < DefaultMinKnownSecretLen {
			continue
		}
		if isBenignEnvValue(val) {
			continue
		}
		if isSecretEnvKeyName(key) || ShannonEntropy(val) >= 3.8 {
			secrets = append(secrets, val)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("proxy: read dotenv file %q: %w", envFilePath, err)
	}
	return secrets, nil
}

// ShannonEntropy computes the base-2 Shannon entropy (bits per byte) of s.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Scan inspects text and returns all non-overlapping secret findings sorted by position.
func (s *Scrubber) Scan(text string) []Finding {
	if text == "" {
		return nil
	}

	excludedSpans := redactedSpanRe.FindAllStringIndex(text, -1)
	var raw []Finding

	// 1. Exact matches against loaded .env / additional secret values.
	for _, secret := range s.knownSecrets {
		offset := 0
		for {
			idx := strings.Index(text[offset:], secret)
			if idx < 0 {
				break
			}
			start := offset + idx
			end := start + len(secret)
			if !overlapsAnyIndex(start, end, excludedSpans) {
				raw = append(raw, Finding{
					Rule:         "known_env_value",
					MatchPreview: maskPreview(secret),
					Start:        start,
					End:          end,
				})
			}
			offset = end
		}
	}

	// 2. High-precision regex detectors.
	for _, rule := range s.rules {
		matches := rule.re.FindAllStringSubmatchIndex(text, -1)
		for _, m := range matches {
			groupStart, groupEnd := m[0], m[1]
			if rule.valueGroup > 0 {
				idx := rule.valueGroup * 2
				if idx+1 >= len(m) || m[idx] < 0 || m[idx+1] < 0 {
					continue
				}
				groupStart, groupEnd = m[idx], m[idx+1]
			}
			if overlapsAnyIndex(groupStart, groupEnd, excludedSpans) {
				continue
			}
			fullMatch := text[m[0]:m[1]]
			val := text[groupStart:groupEnd]
			if rule.filter != nil && !rule.filter(fullMatch, val) {
				continue
			}
			raw = append(raw, Finding{
				Rule:         rule.name,
				MatchPreview: maskPreview(val),
				Start:        groupStart,
				End:          groupEnd,
			})
		}
	}

	merged := deduplicateFindings(raw)

	// 3. Shannon high-entropy scanner on spans not already caught by structured rules.
	if !s.disableEntropy {
		tokenMatches := entropyTokenRe.FindAllStringIndex(text, -1)
		for _, loc := range tokenMatches {
			start, end := loc[0], loc[1]
			if end-start < s.minEntropyTokenLen {
				continue
			}
			if overlapsAnyIndex(start, end, excludedSpans) || overlapsAnyFinding(start, end, merged) {
				continue
			}
			tok := text[start:end]
			if isLikelyNonSecretToken(text, start, end, tok) {
				continue
			}
			ent := ShannonEntropy(tok)
			if ent >= s.entropyThreshold {
				merged = append(merged, Finding{
					Rule:         "high_entropy_token",
					MatchPreview: maskPreview(tok),
					Start:        start,
					End:          end,
					Entropy:      math.Round(ent*100) / 100,
				})
			}
		}
		merged = deduplicateFindings(merged)
	}

	return merged
}

// Scrub scans text and replaces every detected secret with [REDACTED:<rule>].
func (s *Scrubber) Scrub(text string) ScrubResult {
	findings := s.Scan(text)
	if len(findings) == 0 {
		return ScrubResult{
			Clean:    true,
			Redacted: text,
		}
	}

	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, f := range findings {
		if f.Start < cursor {
			continue
		}
		b.WriteString(text[cursor:f.Start])
		fmt.Fprintf(&b, "[REDACTED:%s]", f.Rule)
		cursor = f.End
	}
	b.WriteString(text[cursor:])

	return ScrubResult{
		Clean:    false,
		Redacted: b.String(),
		Findings: findings,
	}
}

// ScanBytes is a byte-slice helper for HTTP request/response bodies.
func (s *Scrubber) ScanBytes(b []byte) []Finding {
	return s.Scan(string(b))
}

// ScrubBytes redacts secrets from b and returns the scrubbed bytes plus findings.
func (s *Scrubber) ScrubBytes(b []byte) ([]byte, []Finding) {
	res := s.Scrub(string(b))
	if res.Clean {
		return b, nil
	}
	return []byte(res.Redacted), res.Findings
}

func deduplicateFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Start != findings[j].Start {
			return findings[i].Start < findings[j].Start
		}
		return findings[i].End > findings[j].End
	})

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if len(out) == 0 {
			out = append(out, f)
			continue
		}
		last := out[len(out)-1]
		if f.Start < last.End {
			// Skip overlapping lower-priority or narrower span.
			continue
		}
		out = append(out, f)
	}
	return out
}

func overlapsAnyIndex(start, end int, spans [][]int) bool {
	for _, sp := range spans {
		if start < sp[1] && end > sp[0] {
			return true
		}
	}
	return false
}

func overlapsAnyFinding(start, end int, findings []Finding) bool {
	for _, f := range findings {
		if start < f.End && end > f.Start {
			return true
		}
	}
	return false
}

func isLikelyNonSecretToken(fullText string, start, end int, tok string) bool {
	// Skip URLs immediately preceding the token (e.g. https://... or http://...).
	prefixStart := start - 16
	if prefixStart < 0 {
		prefixStart = 0
	}
	preceding := fullText[prefixStart:start]
	if strings.Contains(preceding, "://") || strings.HasSuffix(preceding, `\`) {
		return true
	}

	// Check surrounding context for file paths or extensions.
	suffixEnd := end + 12
	if suffixEnd > len(fullText) {
		suffixEnd = len(fullText)
	}
	window := fullText[start:suffixEnd]
	if codeFileExtRe.MatchString(tok) || codeFileExtRe.MatchString(window) {
		return true
	}

	// Leading slash or multiple lowercase path segments indicate a filesystem/URL path.
	if strings.HasPrefix(tok, "/") {
		return true
	}
	if strings.Count(tok, "/") >= 2 && looksLikePathSegments(tok) {
		return true
	}

	// Pure hex strings (Git SHA-1, SHA-256) and UUIDs are common non-secret artifacts.
	if isPureHexOrUUID(tok) {
		return true
	}

	// Require strong character-class diversity (>= 3 of lower, upper, digit, symbol)
	// so camelCase/snake_case code identifiers do not trigger false positives.
	classes := countCharClasses(tok)
	if classes < 3 {
		return true
	}

	return false
}

func looksLikePathSegments(tok string) bool {
	parts := strings.Split(tok, "/")
	wordLike := 0
	for _, p := range parts {
		if p == "" {
			continue
		}
		allLowerWord := true
		for _, r := range p {
			if !(unicode.IsLower(r) || unicode.IsDigit(r) || r == '-' || r == '_') {
				allLowerWord = false
				break
			}
		}
		if allLowerWord {
			wordLike++
		}
	}
	return wordLike >= 2
}

func isPureHexOrUUID(s string) bool {
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex && r != '-' {
			return false
		}
	}
	return true
}

func countCharClasses(s string) int {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	n := 0
	if hasLower {
		n++
	}
	if hasUpper {
		n++
	}
	if hasDigit {
		n++
	}
	if hasSymbol {
		n++
	}
	return n
}

func isPlaceholderOrReference(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" {
		return true
	}
	lower := strings.ToLower(v)
	for _, prefix := range []string{"$", "<", "{{", "[redacted:", "os.getenv", "os.environ", "process.env", "env["} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, marker := range []string{"your_", "example", "changeme", "placeholder", "dummy", "redacted", "xxxx"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	// Skip ALL_CAPS_ENV_VAR_NAME references (e.g. ANTHROPIC_API_KEY).
	if strings.Contains(v, "_") {
		allUpperOrUnderscore := true
		for _, r := range v {
			if !((r >= 'A' && r <= 'Z') || r == '_') {
				allUpperOrUnderscore = false
				break
			}
		}
		if allUpperOrUnderscore {
			return true
		}
	}
	return false
}

func isBenignEnvValue(val string) bool {
	lower := strings.ToLower(strings.TrimSpace(val))
	switch lower {
	case "true", "false", "development", "production", "staging", "testing", "localhost", "127.0.0.1", "0.0.0.0":
		return true
	}
	// Purely numeric values (ports, timeouts, counts) are not secrets.
	allDigits := true
	for _, r := range lower {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	return allDigits
}

func isSecretEnvKeyName(key string) bool {
	upper := strings.ToUpper(key)
	for _, kw := range []string{"KEY", "SECRET", "TOKEN", "PASS", "AUTH", "CREDENTIAL", "PRIVATE", "DATABASE_URL", "DSN"} {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

func stripDotEnvQuotes(val string) string {
	if len(val) >= 2 {
		if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
			return val[1 : len(val)-1]
		}
	}
	// Strip trailing inline comments for unquoted values.
	if idx := strings.Index(val, " #"); idx >= 0 {
		val = strings.TrimSpace(val[:idx])
	}
	return val
}

func maskPreview(raw string) string {
	if len(raw) <= 12 {
		return "***"
	}
	return raw[:4] + "..." + raw[len(raw)-4:]
}
