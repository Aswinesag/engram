package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"engram/internal/store"
)

const (
	EngramDirName                  = ".engram"
	ConfigFileName                 = "config.toml"
	ManifestFileName               = "manifest.json"
	GitIgnoreFileName              = ".gitignore"
	RuntimeDirName                 = ".runtime"
	StateDBFileName                = "state.db"
	DefaultArtifactTokenThreshold  = 2000
	DefaultConsecutiveErrorTrigger = 3
)

var (
	// ErrNotGitRepository is returned when init/load is invoked outside a Git repository.
	ErrNotGitRepository = errors.New("control: target directory is not inside a git repository")

	// ErrWorkspaceNotInitialized is returned when .engram/config.toml does not exist.
	ErrWorkspaceNotInitialized = errors.New("control: .engram workspace is not initialized (run 'engram init')")
)

// Workspace encapsulates canonical paths for a repository's .engram/ directory.
type Workspace struct {
	RepoRoot string
}

func (w Workspace) EngramDir() string    { return filepath.Join(w.RepoRoot, EngramDirName) }
func (w Workspace) ConfigPath() string   { return filepath.Join(w.EngramDir(), ConfigFileName) }
func (w Workspace) ManifestPath() string { return filepath.Join(w.EngramDir(), ManifestFileName) }
func (w Workspace) HooksDir() string     { return filepath.Join(w.EngramDir(), "hooks") }
func (w Workspace) ToolsDir() string     { return filepath.Join(w.EngramDir(), "tools") }
func (w Workspace) RulesDir() string     { return filepath.Join(w.EngramDir(), "rules") }
func (w Workspace) RuntimeDir() string   { return filepath.Join(w.EngramDir(), RuntimeDirName) }
func (w Workspace) StateDBPath() string  { return filepath.Join(w.RuntimeDir(), StateDBFileName) }
func (w Workspace) ArtifactsDir() string { return filepath.Join(w.RuntimeDir(), "artifacts") }
func (w Workspace) WorktreesDir() string { return filepath.Join(w.RuntimeDir(), "worktrees") }

// Config maps directly to .engram/config.toml.
type Config struct {
	Model     ModelConfig     `toml:"model"`
	Context   ContextConfig   `toml:"context"`
	Sandbox   SandboxConfig   `toml:"sandbox"`
	Evolution EvolutionConfig `toml:"evolution"`
}

type ModelConfig struct {
	Provider        string `toml:"provider"`
	Model           string `toml:"model"`
	Endpoint        string `toml:"endpoint"`
	APIKeyEnv       string `toml:"api_key_env"`
	MaxOutputTokens int    `toml:"max_output_tokens"`
}

type ContextConfig struct {
	ArtifactTokenThreshold int `toml:"artifact_token_threshold"`
}

type SandboxConfig struct {
	Mode           string   `toml:"mode"`
	ContainerImage string   `toml:"container_image"`
	AllowedDomains []string `toml:"allowed_domains"`
	RedactSecrets  bool     `toml:"redact_secrets"`
}

type EvolutionConfig struct {
	AutoApproveThreshold    float64 `toml:"auto_approve_threshold"`
	MinShadowPassRate       float64 `toml:"min_shadow_pass_rate"`
	ConsecutiveErrorTrigger int     `toml:"consecutive_error_trigger"`
}

// DefaultConfig returns production-safe defaults matching the Engram v1.1 blueprint.
func DefaultConfig() Config {
	return Config{
		Model: ModelConfig{
			Provider:        "anthropic",
			Model:           "claude-sonnet-4-20250514",
			Endpoint:        "https://api.anthropic.com/v1/messages",
			APIKeyEnv:       "ANTHROPIC_API_KEY",
			MaxOutputTokens: 8192,
		},
		Context: ContextConfig{
			ArtifactTokenThreshold: DefaultArtifactTokenThreshold,
		},
		Sandbox: SandboxConfig{
			Mode:           "native",
			ContainerImage: "ubuntu:24.04",
			AllowedDomains: []string{
				"api.anthropic.com",
				"api.openai.com",
				"pypi.org",
				"files.pythonhosted.org",
				"proxy.golang.org",
				"registry.npmjs.org",
			},
			RedactSecrets: true,
		},
		Evolution: EvolutionConfig{
			AutoApproveThreshold:    1.0,
			MinShadowPassRate:       1.0,
			ConsecutiveErrorTrigger: DefaultConsecutiveErrorTrigger,
		},
	}
}

// Validate checks configuration invariants before runtime execution.
func (c Config) Validate() error {
	switch c.Model.Provider {
	case "anthropic", "openai", "ollama":
	default:
		return fmt.Errorf("control: unsupported model.provider %q (want anthropic, openai, or ollama)", c.Model.Provider)
	}
	if strings.TrimSpace(c.Model.Model) == "" {
		return errors.New("control: model.model must not be empty")
	}
	if c.Context.ArtifactTokenThreshold <= 0 {
		return errors.New("control: context.artifact_token_threshold must be > 0")
	}
	switch c.Sandbox.Mode {
	case "native", "strict":
	default:
		return fmt.Errorf("control: unsupported sandbox.mode %q (want native or strict)", c.Sandbox.Mode)
	}
	if c.Evolution.ConsecutiveErrorTrigger <= 0 {
		return errors.New("control: evolution.consecutive_error_trigger must be > 0")
	}
	return nil
}

// Manifest maps directly to .engram/manifest.json.
type Manifest struct {
	Version string          `json:"version"`
	Hooks   []ManifestEntry `json:"hooks"`
	Tools   []ManifestEntry `json:"tools"`
	Rules   []ManifestEntry `json:"rules"`
}

// ManifestEntry tracks a Git-versioned compiled hook, tool, or scoped rule.
type ManifestEntry struct {
	ID             string             `json:"id"`
	Kind           store.EngramKind   `json:"kind"`
	TargetTool     string             `json:"target_tool,omitempty"`
	TriggerPattern string             `json:"trigger_pattern"`
	FilePath       string             `json:"file_path"`
	Status         store.EngramStatus `json:"status"`
	ShadowPassRate float64            `json:"shadow_pass_rate,omitempty"`
	Explanation    string             `json:"explanation,omitempty"`
}

// DefaultManifest returns an empty versioned manifest registry.
func DefaultManifest() Manifest {
	return Manifest{
		Version: "1.0",
		Hooks:   []ManifestEntry{},
		Tools:   []ManifestEntry{},
		Rules:   []ManifestEntry{},
	}
}

// ResolveRepoRoot locates the top-level Git repository directory containing startDir.
func ResolveRepoRoot(ctx context.Context, startDir string) (string, error) {
	if strings.TrimSpace(startDir) == "" {
		startDir = "."
	}
	absDir, err := filepath.Abs(startDir)
	if err != nil {
		return "", fmt.Errorf("control: resolve directory %q: %w", startDir, err)
	}

	cmd := exec.CommandContext(ctx, "git", "-C", absDir, "rev-parse", "--show-toplevel")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return "", fmt.Errorf("%w: %s", ErrNotGitRepository, msg)
		}
		return "", fmt.Errorf("%w: %v", ErrNotGitRepository, err)
	}

	root := strings.TrimSpace(stdout.String())
	if root == "" {
		return "", ErrNotGitRepository
	}
	return filepath.Clean(filepath.FromSlash(root)), nil
}

// InitWorkspace scaffolds the .engram/ directory, default config.toml,
// manifest.json, .engram/.gitignore, and initializes the SQLite WAL database.
// Existing config.toml and manifest.json files are preserved unless force is true.
func InitWorkspace(ctx context.Context, startDir string, force bool) (Workspace, error) {
	repoRoot, err := ResolveRepoRoot(ctx, startDir)
	if err != nil {
		return Workspace{}, err
	}

	ws := Workspace{RepoRoot: repoRoot}
	dirs := []string{
		ws.EngramDir(),
		ws.HooksDir(),
		ws.ToolsDir(),
		ws.RulesDir(),
		ws.RuntimeDir(),
		ws.ArtifactsDir(),
		ws.WorktreesDir(),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Workspace{}, fmt.Errorf("control: create directory %q: %w", dir, err)
		}
	}

	// Always ensure .engram/.runtime/ is git-ignored inside .engram/.gitignore.
	gitIgnorePath := filepath.Join(ws.EngramDir(), GitIgnoreFileName)
	if err := writeFileIfNeeded(gitIgnorePath, []byte(".runtime/\n"), true); err != nil {
		return Workspace{}, fmt.Errorf("control: write %s: %w", gitIgnorePath, err)
	}

	cfgBytes, err := toml.Marshal(DefaultConfig())
	if err != nil {
		return Workspace{}, fmt.Errorf("control: marshal default config: %w", err)
	}
	if err := writeFileIfNeeded(ws.ConfigPath(), cfgBytes, force); err != nil {
		return Workspace{}, fmt.Errorf("control: write config.toml: %w", err)
	}

	manifestBytes, err := json.MarshalIndent(DefaultManifest(), "", "  ")
	if err != nil {
		return Workspace{}, fmt.Errorf("control: marshal default manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := writeFileIfNeeded(ws.ManifestPath(), manifestBytes, force); err != nil {
		return Workspace{}, fmt.Errorf("control: write manifest.json: %w", err)
	}

	// Initialize SQLite WAL schema immediately.
	st, err := store.Open(ctx, ws.StateDBPath())
	if err != nil {
		return Workspace{}, fmt.Errorf("control: initialize sqlite state store: %w", err)
	}
	if err := st.Close(); err != nil {
		return Workspace{}, fmt.Errorf("control: close sqlite state store: %w", err)
	}

	return ws, nil
}

// LoadWorkspace locates an initialized .engram/ workspace and parses config.toml and manifest.json.
func LoadWorkspace(ctx context.Context, startDir string) (Workspace, Config, Manifest, error) {
	repoRoot, err := ResolveRepoRoot(ctx, startDir)
	if err != nil {
		return Workspace{}, Config{}, Manifest{}, err
	}
	ws := Workspace{RepoRoot: repoRoot}

	cfgData, err := os.ReadFile(ws.ConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return Workspace{}, Config{}, Manifest{}, ErrWorkspaceNotInitialized
	}
	if err != nil {
		return Workspace{}, Config{}, Manifest{}, fmt.Errorf("control: read config.toml: %w", err)
	}

	var cfg Config
	if err := toml.Unmarshal(cfgData, &cfg); err != nil {
		return Workspace{}, Config{}, Manifest{}, fmt.Errorf("control: parse config.toml: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Workspace{}, Config{}, Manifest{}, err
	}

	manifest := DefaultManifest()
	manifestData, err := os.ReadFile(ws.ManifestPath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Workspace{}, Config{}, Manifest{}, fmt.Errorf("control: read manifest.json: %w", err)
	}
	if err == nil {
		if err := json.Unmarshal(manifestData, &manifest); err != nil {
			return Workspace{}, Config{}, Manifest{}, fmt.Errorf("control: parse manifest.json: %w", err)
		}
	}

	return ws, cfg, manifest, nil
}

// SaveManifest atomically writes manifest.json inside the workspace.
func SaveManifest(ws Workspace, m Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("control: marshal manifest: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(ws.EngramDir(), "manifest-*.tmp")
	if err != nil {
		return fmt.Errorf("control: create temp manifest: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("control: write temp manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("control: close temp manifest: %w", err)
	}
	if err := os.Rename(tmpPath, ws.ManifestPath()); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("control: replace manifest.json: %w", err)
	}
	return nil
}

func writeFileIfNeeded(path string, content []byte, overwrite bool) error {
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
	}
	return os.WriteFile(path, content, 0o644)
}
