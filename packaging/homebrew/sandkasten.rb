# Homebrew formula for sandkasten.
#
# Usage:
#   brew tap DatanoiseTV/sandkasten
#   brew install sandkasten
#
# This file is the canonical template. A release is cut by:
#   1. tagging a new version (e.g. `git tag v0.2.0 && git push --tags`)
#   2. updating `url` and the sha256 below to match the release tarball
#   3. committing the bumped formula to the tap repo
#      (https://github.com/DatanoiseTV/homebrew-sandkasten)

class Sandkasten < Formula
  desc     "Fast, kernel-enforced application sandbox for macOS and Linux"
  homepage "https://github.com/DatanoiseTV/sandkasten"
  license  "MIT OR Apache-2.0"
  head     "https://github.com/DatanoiseTV/sandkasten.git", branch: "main"

  # Stable release — update on each tag.
  # url    "https://github.com/DatanoiseTV/sandkasten/archive/refs/tags/v0.1.0.tar.gz"
  # sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  # version "0.1.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args

    # Shell completions shipped alongside the binary.
    generate_completions_from_executable(bin/"sandkasten", "completions")
  end

  test do
    # Smoke test: templates list is stable and non-empty.
    assert_match "self", shell_output("#{bin}/sandkasten templates")
    # Pre-flight check exits 0 on a healthy host.
    system "#{bin}/sandkasten", "doctor"
  end
end
