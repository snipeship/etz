#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <version> <repo> <checksums_file> <output_file>" >&2
  exit 1
fi

VERSION="$1"
REPO="$2"
CHECKSUMS_FILE="$3"
OUTPUT_FILE="$4"

if [ ! -f "$CHECKSUMS_FILE" ]; then
  echo "checksums file not found: $CHECKSUMS_FILE" >&2
  exit 1
fi

sha_for_target() {
  local target="$1"
  local file="etz-${VERSION}-${target}.tar.gz"
  awk -v f="$file" '$2 == f { print $1 }' "$CHECKSUMS_FILE"
}

LINUX_SHA="$(sha_for_target "x86_64-unknown-linux-gnu")"
MACOS_INTEL_SHA="$(sha_for_target "x86_64-apple-darwin")"
MACOS_ARM_SHA="$(sha_for_target "aarch64-apple-darwin")"

if [ -z "$LINUX_SHA" ] || [ -z "$MACOS_INTEL_SHA" ] || [ -z "$MACOS_ARM_SHA" ]; then
  echo "missing checksums in $CHECKSUMS_FILE" >&2
  exit 1
fi

cat >"$OUTPUT_FILE" <<EOF
class Etz < Formula
  desc "CLI for coordinating git worktrees across multi-repo parent directories"
  homepage "https://github.com/snipeship/etz"
  version "${VERSION}"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/${REPO}/releases/download/v${VERSION}/etz-${VERSION}-aarch64-apple-darwin.tar.gz"
      sha256 "${MACOS_ARM_SHA}"
    else
      url "https://github.com/${REPO}/releases/download/v${VERSION}/etz-${VERSION}-x86_64-apple-darwin.tar.gz"
      sha256 "${MACOS_INTEL_SHA}"
    end
  end

  on_linux do
    url "https://github.com/${REPO}/releases/download/v${VERSION}/etz-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "${LINUX_SHA}"
  end

  def install
    bin.install "etz"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/etz --version")
  end
end
EOF
