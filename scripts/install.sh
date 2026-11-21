#!/usr/bin/env sh
set -eu

# Engram one-line installer for macOS and Linux.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/engram-ai/engram/main/scripts/install.sh | sh
# Optional env overrides:
#   ENGRAM_REPO="owner/engram"
#   ENGRAM_VERSION="v1.0.0" (defaults to latest release)
#   ENGRAM_INSTALL_DIR="$HOME/.local/bin"

ENGRAM_REPO="${ENGRAM_REPO:-engram-ai/engram}"
ENGRAM_VERSION="${ENGRAM_VERSION:-latest}"
ENGRAM_INSTALL_DIR="${ENGRAM_INSTALL_DIR:-$HOME/.local/bin}"

log() {
  printf '[engram-install] %s\n' "$1"
}

fail() {
  printf '[engram-install] error: %s\n' "$1" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

detect_os() {
  case "$(uname -s)" in
    Darwin) printf 'darwin' ;;
    Linux)  printf 'linux' ;;
    *)      fail "unsupported OS: $(uname -s) (use PowerShell / GoReleaser zip on Windows)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)   printf 'amd64' ;;
    arm64|aarch64)  printf 'arm64' ;;
    *)              fail "unsupported architecture: $(uname -m)" ;;
  esac
}

verify_sha256() {
  file_path="$1"
  expected="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file_path" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file_path" | awk '{print $1}')"
  else
    fail "neither sha256sum nor shasum found for checksum verification"
  fi
  if [ "$actual" != "$expected" ]; then
    fail "checksum mismatch for $file_path (expected $expected, got $actual)"
  fi
}

resolve_version() {
  if [ "$ENGRAM_VERSION" != "latest" ]; then
    printf '%s' "${ENGRAM_VERSION#v}"
    return
  fi
  api_url="https://api.github.com/repos/${ENGRAM_REPO}/releases/latest"
  tag="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$tag" ] || fail "could not determine latest release tag from $api_url"
  printf '%s' "${tag#v}"
}

main() {
  need_cmd curl
  need_cmd tar

  os="$(detect_os)"
  arch="$(detect_arch)"
  version="$(resolve_version)"
  tag="v${version}"

  archive="engram_${version}_${os}_${arch}.tar.gz"
  base_url="https://github.com/${ENGRAM_REPO}/releases/download/${tag}"

  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  log "Downloading ${archive} (${tag})..."
  curl -fsSL "${base_url}/${archive}" -o "${tmp_dir}/${archive}"
  curl -fsSL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt"

  expected_sum="$(grep " ${archive}\$" "${tmp_dir}/checksums.txt" | awk '{print $1}' | head -n 1)"
  [ -n "$expected_sum" ] || fail "archive ${archive} not found in checksums.txt"

  log "Verifying SHA-256 checksum..."
  verify_sha256 "${tmp_dir}/${archive}" "$expected_sum"

  log "Extracting to ${ENGRAM_INSTALL_DIR}..."
  mkdir -p "${ENGRAM_INSTALL_DIR}"
  tar -xzf "${tmp_dir}/${archive}" -C "${tmp_dir}"
  install -m 0755 "${tmp_dir}/engram" "${ENGRAM_INSTALL_DIR}/engram"

  log "Installed engram ${tag} to ${ENGRAM_INSTALL_DIR}/engram"

  # Optionally install the Python Evolution Compiler wheel if uv is present.
  if command -v uv >/dev/null 2>&1; then
    wheel_name="engram_compiler-${version}-py3-none-any.whl"
    if curl -fsSL "${base_url}/${wheel_name}" -o "${tmp_dir}/${wheel_name}" 2>/dev/null; then
      log "Installing Python Evolution Compiler via uv tool..."
      uv tool install --force "${tmp_dir}/${wheel_name}" >/dev/null 2>&1 || true
    fi
  fi

  case ":${PATH}:" in
    *":${ENGRAM_INSTALL_DIR}:"*) ;;
    *)
      printf '\nAdd Engram to your PATH:\n  export PATH="%s:$PATH"\n' "${ENGRAM_INSTALL_DIR}"
      ;;
  esac

  "${ENGRAM_INSTALL_DIR}/engram" --help >/dev/null
  log "Ready! Run 'engram init' inside any Git repository."
}

main "$@"