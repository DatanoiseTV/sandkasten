# Verifying a sandkasten release

Every tagged release ships four independent integrity layers. You need
**none** of them to use sandkasten — but if you're integrating it into
a security-sensitive environment, here's what's actually proven and
how to check it.

## TL;DR

```sh
TAG=v0.4.0
TRIPLE=x86_64-unknown-linux-gnu
F=sandkasten-${TAG}-${TRIPLE}.tar.gz

# 1. SHA-256
curl -sSLO https://github.com/DatanoiseTV/sandkasten/releases/download/${TAG}/${F}.sha256
shasum -a 256 -c ${F}.sha256

# 2. Sigstore signature (recommended)
cosign verify-blob ${F} \
  --signature   ${F}.sig \
  --certificate ${F}.cert.pem \
  --certificate-identity-regexp 'https://github.com/DatanoiseTV/sandkasten/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# 3. GitHub build provenance (SLSA)
gh attestation verify ${F} --owner DatanoiseTV
```

## What each layer proves

### 1. SHA-256 (`*.sha256`)

> "The bytes I downloaded are the same bytes the release workflow
> uploaded."

Cheapest check. Doesn't prove the release came from us — only that
the download wasn't corrupted in transit. Mirror this against the
hash printed in the release notes (which GitHub serves over TLS from
its own infrastructure) for a useful trust path.

### 2. Sigstore keyless signing (`*.sig` + `*.cert.pem`)

> "This artefact was produced by a GitHub Actions workflow run in the
> `DatanoiseTV/sandkasten` repository. The signing key is short-lived
> (it expires within minutes of the run) and the signature event is
> recorded in the public Rekor transparency log."

The strongest of the three layers and the one we recommend by default
for security-critical use. No long-lived keys to manage, no rotation,
no key-compromise blast radius — every release run gets a fresh
keypair issued by the public sigstore Fulcio CA, the binary is signed
within seconds, and the certificate is discarded. The signature plus
certificate are durable artefacts that anyone can verify offline.

The `--certificate-identity-regexp` flag is what binds the signature
to the project: it requires the cert's SAN to match a workflow run
under `DatanoiseTV/sandkasten`. Tighten this further to a specific
workflow file (e.g. `https://github.com/DatanoiseTV/sandkasten/.github/workflows/release.yml@refs/tags/v0.4.0`)
if you want to also rule out signatures produced from a fork or a
non-release workflow.

To inspect the certificate without verifying:

```sh
openssl x509 -in ${F}.cert.pem -text -noout | head -40
```

### 3. GitHub build provenance (SLSA)

> "This artefact is the output of a specific GitHub Actions workflow
> run, on a specific commit, with the specific build inputs the
> attestation describes."

Verifiable end-to-end with `gh attestation verify`. The attestation
predicate (`https://slsa.dev/provenance/v1`) records the workflow file
path, the trigger event, the runner image, and the source commit SHA.
This is what answers the question "did the bytes I'm running come
from a build I can audit?" — the SBOM (next layer) tells you what's
*in* those bytes; the provenance tells you *how they got there*.

### 4. SBOM (`sandkasten-${TAG}.cdx.json`)

CycloneDX 1.4 software bill-of-materials covering every crate the
binary was built from, with versions, licenses, and source registries.
Ingest with any SBOM-aware tooling (`grype`, `syft`, `trivy`, vendor
scanners). Useful for:

- License compliance audits.
- CVE matching against `cargo-audit`-equivalent feeds.
- Detecting supply-chain regressions across releases (diff two SBOMs
  with `syft diff` or `cyclonedx diff`).

The same SBOM is regenerated on every CI run (`supply-chain` job in
`ci.yml`) and uploaded as a workflow artefact, so you can verify it
matches the release-attached copy if you're paranoid.

## How `cargo-deny` ties in

The `supply-chain` CI job runs `cargo deny check` on every push using
the policy at `deny.toml` in the repo root. It enforces:

- No advisories from the RustSec database (any pulled CVE is a hard
  CI fail).
- License allow-list (every transitive dep must declare a license
  matching one of the entries in `[licenses]` of `deny.toml`).
- Source registries restricted to crates.io — git or alternative
  registries are rejected by default.
- `wildcard` version requirements are denied.

A green CI on the release commit means none of the above triggered.

## Reproducing builds locally

```sh
git clone https://github.com/DatanoiseTV/sandkasten.git
cd sandkasten
git checkout v0.4.0
cargo build --release --target x86_64-unknown-linux-gnu
```

A bit-for-bit reproducible-build claim is **not** part of this
release process today — Rust's release builds are not deterministic
across builder hosts (compiler version, debug-info paths, link
order). What we do guarantee is that the source tree at the tag
plus the workflow definition at that tag fully describe the build;
provenance attestations bind those two things to the published
artefact.

## Bug reports

If `cosign verify-blob` or `gh attestation verify` fails on an
artefact you downloaded directly from the GitHub Releases page,
that's a security incident. Open an issue tagged `security` on the
upstream repository — don't post the failing artefact contents
publicly until we've replied.
