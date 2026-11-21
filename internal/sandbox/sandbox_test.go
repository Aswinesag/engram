package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSanitizeEnvironmentStripsSecretsAndInjectsProxy(t *testing.T) {
	base := []string{
		"PATH=/usr/bin:/bin",
		"ANTHROPIC_API_KEY=sk-ant-super-secret",
		"OPENAI_API_KEY=sk-proj-super-secret",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"DATABASE_URL=postgres://user:pass@localhost/db",
		"GITHUB_TOKEN=ghp_1234567890",
		"HTTP_PROXY=http://old-proxy:8080",
	}
	proxyEnv := []string{
		"HTTP_PROXY=http://127.0.0.1:41234",
		"HTTPS_PROXY=http://127.0.0.1:41234",
		"ALL_PROXY=socks5h://127.0.0.1:41235",
	}

	got := SanitizeEnvironment(base, false, proxyEnv, []string{"ENGRAM_TEST=1"})
	joined := strings.Join(got, "\n")

	for _, forbidden := range []string{
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"AWS_SECRET_ACCESS_KEY",
		"DATABASE_URL",
		"GITHUB_TOKEN",
		"old-proxy",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("SanitizeEnvironment leaked %q:\n%s", forbidden, joined)
		}
	}

	for _, required := range []string{
		"PATH=/usr/bin:/bin",
		"HTTP_PROXY=http://127.0.0.1:41234",
		"HTTPS_PROXY=http://127.0.0.1:41234",
		"ALL_PROXY=socks5h://127.0.0.1:41235",
		"ENGRAM_TEST=1",
	} {
		if !slices.Contains(got, required) {
			t.Fatalf("SanitizeEnvironment missing %q:\n%s", required, joined)
		}
	}
}

func TestBuildContainerArgsHardeningAndProxyRouting(t *testing.T) {
	wt := "/repo/.engram/.runtime/worktrees/sess_123"

	// 1. Offline mode (no proxy, AllowNetwork=false) -> --network=none.
	offlineArgs := BuildContainerArgs(Config{
		Mode:           ModeStrict,
		ContainerImage: "ubuntu:24.04",
		AllowNetwork:   false,
	}, wt, "pytest tests/", []string{"AWS_SECRET_ACCESS_KEY=leaked", "PYTEST_ADDOPTS=-q"})

	offlineStr := strings.Join(offlineArgs, " ")
	for _, want := range []string{
		"--rm",
		"--cap-drop=ALL",
		"--security-opt=no-new-privileges:true",
		"--read-only",
		"-v " + wt + ":/workspace:rw",
		"-w /workspace",
		"--network=none",
		"-e PYTEST_ADDOPTS=-q",
	} {
		if !strings.Contains(offlineStr, want) {
			t.Fatalf("offline container args missing %q:\n%s", want, offlineStr)
		}
	}
	if strings.Contains(offlineStr, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("container args leaked secret env var:\n%s", offlineStr)
	}

	// 2. Proxy mode -> host.docker.internal rewrite + --add-host, without --network=none.
	proxyArgs := BuildContainerArgs(Config{
		Mode:           ModeStrict,
		ContainerImage: "python:3.12-slim",
		ProxyEnv: []string{
			"HTTP_PROXY=http://127.0.0.1:50001",
			"ALL_PROXY=socks5h://127.0.0.1:50002",
		},
	}, wt, "pip list", nil)

	proxyStr := strings.Join(proxyArgs, " ")
	for _, want := range []string{
		"--add-host=host.docker.internal:host-gateway",
		"-e HTTP_PROXY=http://host.docker.internal:50001",
		"-e ALL_PROXY=socks5h://host.docker.internal:50002",
	} {
		if !strings.Contains(proxyStr, want) {
			t.Fatalf("proxy container args missing %q:\n%s", want, proxyStr)
		}
	}
	if strings.Contains(proxyStr, "--network=none") {
		t.Fatalf("proxy container args should not set --network=none:\n%s", proxyStr)
	}
}

func TestBuildSeatbeltProfileAndBubblewrapArgs(t *testing.T) {
	wt := "/Users/dev/payments-api/.engram/.runtime/worktrees/sess_1"

	profile := BuildSeatbeltProfile(wt, true)
	for _, want := range []string{
		"(deny default)",
		`(allow file-write* (subpath "` + wt + `"))`,
		`(allow network-outbound (remote ip "127.0.0.1:*"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("Seatbelt profile missing %q:\n%s", want, profile)
		}
	}

	offlineProfile := BuildSeatbeltProfile(wt, false)
	if strings.Contains(offlineProfile, "network-outbound") {
		t.Fatalf("offline Seatbelt profile must not allow network-outbound:\n%s", offlineProfile)
	}

	bwrapArgs := BuildBubblewrapArgs(wt, "pytest", false, []string{"/usr", "/bin"})
	bwrapStr := strings.Join(bwrapArgs, " ")
	for _, want := range []string{
		"--die-with-parent",
		"--unshare-pid",
		"--unshare-net",
		"--ro-bind /usr /usr",
		"--bind " + wt + " " + wt,
		"--chdir " + wt,
	} {
		if !strings.Contains(bwrapStr, want) {
			t.Fatalf("bwrap args missing %q:\n%s", want, bwrapStr)
		}
	}
}

func TestNativeRunnerIsolatesEnvAndPropagatesExitCodes(t *testing.T) {
	wt := t.TempDir()
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-do-not-leak-into-sandbox")

	runner, err := NewRunner(Config{
		Mode: ModeNative,
		ProxyEnv: []string{
			"HTTP_PROXY=http://127.0.0.1:49999",
		},
	})
	if err != nil {
		t.Fatalf("NewRunner(native) error = %v", err)
	}

	// Verify secret env var is stripped while HTTP_PROXY is injected.
	checkCmd := `echo "KEY=${ANTHROPIC_API_KEY} PROXY=${HTTP_PROXY}"`
	if runtime.GOOS == "windows" {
		checkCmd = `echo KEY=%ANTHROPIC_API_KEY% PROXY=%HTTP_PROXY%`
	}
	res, err := runner.Run(context.Background(), ExecRequest{
		Command:      checkCmd,
		WorktreePath: wt,
		Timeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("runner.Run(env check) error = %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, output = %q", res.ExitCode, res.Output)
	}
	if strings.Contains(res.Output, "sk-ant-do-not-leak-into-sandbox") {
		t.Fatalf("sandbox leaked host ANTHROPIC_API_KEY into child process:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "http://127.0.0.1:49999") {
		t.Fatalf("sandbox missing injected HTTP_PROXY:\n%s", res.Output)
	}

	// Verify file creation occurs inside worktreePath.
	writeCmd := `echo ok > probe.txt`
	resWrite, err := runner.Run(context.Background(), ExecRequest{
		Command:      writeCmd,
		WorktreePath: wt,
		Timeout:      10 * time.Second,
	})
	if err != nil || resWrite.ExitCode != 0 {
		t.Fatalf("write probe failed: res=%+v err=%v", resWrite, err)
	}
	if _, err := os.Stat(filepath.Join(wt, "probe.txt")); err != nil {
		t.Fatalf("probe.txt missing in worktree: %v", err)
	}

	// Verify non-zero exit code propagation.
	resFail, err := runner.Run(context.Background(), ExecRequest{
		Command:      "exit 9",
		WorktreePath: wt,
		Timeout:      10 * time.Second,
	})
	if err != nil {
		t.Fatalf("runner.Run(exit 9) unexpected error = %v", err)
	}
	if resFail.ExitCode != 9 {
		t.Fatalf("ExitCode = %d, want 9", resFail.ExitCode)
	}
}
