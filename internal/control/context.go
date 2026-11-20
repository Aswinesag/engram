package control

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// CompactResult captures the outcome of applying Strict Context Hygiene (Invariant #5)
// to a raw tool output before injecting it into the LLM context window.
type CompactResult struct {
	Summary         string
	RawArtifactPath string
	Spilled         bool
	EstimatedTokens int
}

// ContextCompactor enforces Invariant #5 by spilling raw tool outputs that exceed
// TokenThreshold into .engram/.runtime/artifacts/ and returning a bounded summary pointer.
type ContextCompactor struct {
	artifactsDir   string
	tokenThreshold int
}

// NewContextCompactor constructs a ContextCompactor. If tokenThreshold <= 0,
// DefaultArtifactTokenThreshold (2,000 tokens) is used.
func NewContextCompactor(artifactsDir string, tokenThreshold int) (*ContextCompactor, error) {
	if strings.TrimSpace(artifactsDir) == "" {
		return nil, fmt.Errorf("control: artifactsDir must not be empty")
	}
	if tokenThreshold <= 0 {
		tokenThreshold = DefaultArtifactTokenThreshold
	}
	return &ContextCompactor{
		artifactsDir:   filepath.Clean(artifactsDir),
		tokenThreshold: tokenThreshold,
	}, nil
}

// EstimateTokens provides a deterministic, zero-dependency token estimate
// (~4 bytes per token, rounded up).
func EstimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	return (len(text) + 3) / 4
}

// Compact inspects rawOutput. If its estimated token count is within the configured
// budget, it is returned verbatim. Otherwise, the full payload is written to disk in
// .engram/.runtime/artifacts/ and a bounded head+tail summary with an artifact pointer
// is returned for the LLM context.
func (c *ContextCompactor) Compact(sessionID string, stepIndex int, toolName, rawOutput string) (CompactResult, error) {
	tokens := EstimateTokens(rawOutput)
	if tokens <= c.tokenThreshold {
		return CompactResult{
			Summary:         rawOutput,
			Spilled:         false,
			EstimatedTokens: tokens,
		}, nil
	}

	if err := os.MkdirAll(c.artifactsDir, 0o755); err != nil {
		return CompactResult{}, fmt.Errorf("control: create artifacts dir: %w", err)
	}

	filename := fmt.Sprintf("%s_step_%04d_%s.log",
		sanitizeFilenameComponent(sessionID),
		stepIndex,
		sanitizeFilenameComponent(toolName),
	)
	artifactPath := filepath.Join(c.artifactsDir, filename)

	if err := os.WriteFile(artifactPath, []byte(rawOutput), 0o644); err != nil {
		return CompactResult{}, fmt.Errorf("control: write artifact %q: %w", artifactPath, err)
	}

	summary := buildCompactedSummary(rawOutput, artifactPath, tokens, c.tokenThreshold)
	return CompactResult{
		Summary:         summary,
		RawArtifactPath: artifactPath,
		Spilled:         true,
		EstimatedTokens: tokens,
	}, nil
}

func buildCompactedSummary(rawOutput, artifactPath string, estimatedTokens, threshold int) string {
	// Keep the injected summary well under the token budget while preserving both
	// the initial context (head) and final failure lines/tracebacks (tail).
	maxSnippetBytes := threshold * 2
	if maxSnippetBytes > 2400 {
		maxSnippetBytes = 2400
	}
	if maxSnippetBytes < 160 {
		maxSnippetBytes = 160
	}

	headBudget := (maxSnippetBytes * 2) / 5
	tailBudget := maxSnippetBytes - headBudget

	head := truncateUTF8Prefix(rawOutput, headBudget)
	tail := truncateUTF8Suffix(rawOutput, tailBudget)
	lineCount := strings.Count(rawOutput, "\n") + 1

	var b strings.Builder
	fmt.Fprintf(&b, "[output truncated: ~%d tokens (%d bytes, %d lines) exceeded %d-token context budget]\n",
		estimatedTokens, len(rawOutput), lineCount, threshold)
	fmt.Fprintf(&b, "[full raw artifact saved to: %s]\n", filepath.ToSlash(artifactPath))
	b.WriteString("--- HEAD ---\n")
	b.WriteString(strings.TrimRight(head, "\r\n"))
	b.WriteString("\n--- TRUNCATED ---\n")
	b.WriteString(strings.TrimLeft(tail, "\r\n"))
	b.WriteString("\n--- END ---")
	return b.String()
}

func truncateUTF8Prefix(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func truncateUTF8Suffix(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	start := len(s) - maxBytes
	for start < len(s) && !utf8.RuneStart(s[start]) {
		start++
	}
	return s[start:]
}

func sanitizeFilenameComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
