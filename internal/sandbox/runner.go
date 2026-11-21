package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const DefaultTimeout = 60 * time.Second

// Mode mirrors sandbox.mode in .engram/config.toml.
type Mode string

const (
	ModeNative Mode = "native"
	ModeStrict Mode = "strict"
)

var (
	// ErrInvalidWorktree is returned when ExecRequest.WorktreePath is missing or not a directory.
	ErrInvalidWorktree = errors.New("sandbox: invalid worktree path")

	// ErrContainerRuntimeNotFound is returned in strict mode when neither docker nor podman is in PATH.
	ErrContainerRuntimeNotFound = errors.New("sandbox: neither docker nor podman found in PATH")
)

// Config configures dual-mode sandboxing and egress proxy injection.
type Config struct {
	Mode             Mode
	ContainerImage   string
	ContainerRuntime string   // Optional explicit "docker" or "podman"
	ProxyEnv         []string // Typically proxy.EgressProxy.ProxyEnv()
	AllowNetwork     bool     // When false and ProxyEnv is empty, strict/bwrap disable networking
	KeepHostSecrets  bool     // Default false: strips secret env vars from child processes
}

// ExecRequest describes a single command execution inside an isolated session worktree.
type ExecRequest struct {
	Command      string
	WorktreePath string
	Timeout      time.Duration
	Env          []string
}

// ExecResult captures combined output, process exit code, and active isolation backend.
type ExecResult struct {
	Output   string
	ExitCode int
	TimedOut bool
	Backend  string
}

// Runner is the unified interface implemented by Native Fast Mode and Strict Container Mode.
type Runner interface {
	Run(ctx context.Context, req ExecRequest) (ExecResult, error)
	Backend() string
}

// NewRunner constructs either a StrictRunner (Docker/Podman) or NativeRunner
// (Seatbelt / Bubblewrap / Windows restricted) according to cfg.Mode.
func NewRunner(cfg Config) (Runner, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeNative
	}
	switch mode {
	case ModeStrict:
		return NewStrictRunner(cfg)
	case ModeNative:
		return NewNativeRunner(cfg)
	default:
		return nil, fmt.Errorf("sandbox: unsupported mode %q (want %q or %q)", mode, ModeNative, ModeStrict)
	}
}

func validateExecRequest(req ExecRequest) (string, time.Duration, error) {
	if strings.TrimSpace(req.Command) == "" {
		return "", 0, errors.New("sandbox: command must not be empty")
	}
	if strings.TrimSpace(req.WorktreePath) == "" {
		return "", 0, fmt.Errorf("%w: empty path", ErrInvalidWorktree)
	}
	absWT, err := filepath.Abs(req.WorktreePath)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrInvalidWorktree, err)
	}
	if resolved, err := filepath.EvalSymlinks(absWT); err == nil {
		absWT = resolved
	}
	info, err := os.Stat(absWT)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrInvalidWorktree, err)
	}
	if !info.IsDir() {
		return "", 0, fmt.Errorf("%w: %q is not a directory", ErrInvalidWorktree, absWT)
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return filepath.Clean(absWT), timeout, nil
}

// SanitizeEnvironment builds a child environment that strips host credentials
// (API keys, cloud secrets, DB passwords, tokens) unless keepSecrets is true,
// and overlays proxyEnv and extraEnv cleanly without duplicate keys.
func SanitizeEnvironment(baseEnv []string, keepSecrets bool, proxyEnv, extraEnv []string) []string {
	type entry struct {
		key string
		val string
	}
	var order []string
	values := make(map[string]entry, len(baseEnv)+len(proxyEnv)+len(extraEnv))

	normKey := func(k string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(k)
		}
		return k
	}

	setKV := func(kv string) {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return
		}
		nk := normKey(k)
		if _, exists := values[nk]; !exists {
			order = append(order, nk)
		}
		values[nk] = entry{key: k, val: v}
	}

	for _, kv := range baseEnv {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if !keepSecrets && isSensitiveEnvKey(k) {
			continue
		}
		setKV(kv)
	}

	for _, kv := range proxyEnv {
		setKV(kv)
	}
	for _, kv := range extraEnv {
		setKV(kv)
	}

	out := make([]string, 0, len(order))
	for _, nk := range order {
		e := values[nk]
		out = append(out, e.key+"="+e.val)
	}
	return out
}

// RewriteProxyEnvForContainer rewrites localhost/127.0.0.1 proxy URLs to
// host.docker.internal so ephemeral containers reach Engram's local Go EgressProxy.
func RewriteProxyEnvForContainer(proxyEnv []string) []string {
	if len(proxyEnv) == 0 {
		return nil
	}
	out := make([]string, 0, len(proxyEnv))
	for _, kv := range proxyEnv {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		upper := strings.ToUpper(k)
		if strings.HasSuffix(upper, "_PROXY") && upper != "NO_PROXY" {
			v = strings.ReplaceAll(v, "127.0.0.1", "host.docker.internal")
			v = strings.ReplaceAll(v, "localhost", "host.docker.internal")
		}
		out = append(out, k+"="+v)
	}
	return out
}

func isSensitiveEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return false
	}

	// Preserve non-secret shell/OS runtime keys explicitly.
	switch upper {
	case "PATH", "HOME", "USER", "USERNAME", "USERPROFILE", "SHELL", "TERM",
		"LANG", "TMP", "TEMP", "TMPDIR", "SYSTEMROOT", "WINDIR", "COMSPEC",
		"PATHEXT", "GOPATH", "GOMODCACHE", "GOCACHE", "VIRTUAL_ENV", "PYTHONPATH",
		"NODE_PATH", "PWD", "SHLVL":
		return false
	}

	sensitiveSubstrings := []string{
		"KEY",
		"SECRET",
		"TOKEN",
		"PASS",
		"CREDENTIAL",
		"PRIVATE",
		"AUTH",
		"COOKIE",
		"SESSION",
		"DATABASE_URL",
		"DSN",
		"ANTHROPIC",
		"OPENAI",
		"GEMINI",
		"AWS_",
		"AZURE_",
		"GCP_",
		"GOOGLE_APPLICATION",
		"GITHUB_",
		"GITLAB_",
		"STRIPE_",
		"SLACK_",
		"NPM_TOKEN",
		"PYPI_",
		"SSH_",
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}
