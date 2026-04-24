# Homebrew formula for sandkasten.
#
# This file is the canonical template. The live copy lives in the tap at
# https://github.com/DatanoiseTV/homebrew-sandkasten/blob/main/Formula/sandkasten.rb
# and is structured so it can be submitted unchanged to homebrew-core
# once the project meets the notability threshold (see SUBMISSION.md).
#
# Install path: the prebuilt release tarball — same binary the GitHub
# Release ships, no local `cargo install` required, ~2s install instead
# of ~45s. Users who want to build from source can clone the repo and
# `cargo install --path .` themselves; we don't bother with a --HEAD
# formula path.
#
# To cut a release:
#   1. tag a new version (e.g. `git tag v0.4.1 && git push --tags`)
#   2. the release workflow builds + uploads 4 platform tarballs + .sha256
#   3. update the url + sha256 for each of the 4 `on_*` blocks
#   4. copy this file to the tap repo

class Sandkasten < Formula
  desc     "Fast, kernel-enforced application sandbox for macOS and Linux"
  homepage "https://github.com/DatanoiseTV/sandkasten"
  license  any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/DatanoiseTV/sandkasten/releases/download/v0.4.0/sandkasten-v0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "a9384e5bb23c67edac0bf2431225ff66d4f20fcc111d53d461cb8d2f0c6c9de8"
    end
    on_intel do
      url "https://github.com/DatanoiseTV/sandkasten/releases/download/v0.4.0/sandkasten-v0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "89b45c4a1de00b8ea72c3f07d36044b1a755541e45dd57a252a40c425d49720d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/DatanoiseTV/sandkasten/releases/download/v0.4.0/sandkasten-v0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "37dcdb08c1a960b4733c9ed2bbb1a5de0147fd287a19062d4c57baf9a1f76336"
    end
    on_intel do
      url "https://github.com/DatanoiseTV/sandkasten/releases/download/v0.4.0/sandkasten-v0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "265561afb7bae9ea81193dfa9d6ed9114e3815043b08ef12e8a5c0ef741c5e1c"
    end
  end

  def install
    bin.install "sandkasten"

    # Shell completions are generated only on the two "native" triples
    # (arm64-macos and x86_64-linux) by release.yml — the build host runs
    # the binary at package time to produce them. Intel-macos and
    # arm64-linux tarballs don't ship completions because we don't run
    # foreign binaries on the build runner. Check existence before
    # installing so the formula works for all four platforms.
    if File.exist?("completions/sandkasten.bash")
      bash_completion.install "completions/sandkasten.bash" => "sandkasten"
    end
    zsh_completion.install "completions/_sandkasten" if File.exist?("completions/_sandkasten")
    fish_completion.install "completions/sandkasten.fish" if File.exist?("completions/sandkasten.fish")
  end

  test do
    assert_match "self", shell_output("#{bin/"sandkasten"} templates")
    system bin/"sandkasten", "doctor"
  end
end
