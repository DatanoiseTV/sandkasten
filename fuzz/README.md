# sandkasten fuzz harness

`libfuzzer-sys` + `cargo-fuzz` over the parse-prone surfaces of the
binary. Targets:

- `profile_parse` — TOML profile loader (deserialise + finalise).
  Largest attacker-controlled-shaped surface. Seeded with every
  bundled `examples/*.toml` + every built-in template.
- `parse_endpoint` — `host:port` / `[v6]:port` / wildcard parser
  used for `outbound_tcp`, `inbound_tcp`, `inbound_udp`.

## One-time setup

`cargo-fuzz` requires a nightly toolchain (sanitisers + the
`-Z sanitizer` flag aren't on stable). The repo's primary build is
stable; nightly is only needed when running fuzz.

```sh
# If you don't already have rustup managing your toolchains:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

rustup install nightly
cargo install cargo-fuzz   # one-off
```

Then from the repo root:

```sh
cargo +nightly fuzz run profile_parse
cargo +nightly fuzz run parse_endpoint
```

Hand-curated starting inputs live in `seeds/<target>/` and are
checked in. Tell cargo-fuzz to use them on the first run:

```sh
cargo +nightly fuzz run profile_parse fuzz/seeds/profile_parse
```

After the first run cargo-fuzz manages a working `corpus/<target>/`
that grows as it discovers new coverage. Crashes land in
`fuzz/artifacts/<target>/`. Both `corpus/` and `artifacts/` are
gitignored.

## Time-boxed run

```sh
cargo +nightly fuzz run profile_parse -- -max_total_time=300
```

Five minutes is enough to surface most low-hanging panics on a
laptop. CI runs longer windows on a cron schedule (TODO).

## Reducing a crash

When libfuzzer reports a crash, it dumps the input as
`fuzz/artifacts/<target>/crash-<sha>`:

```sh
cargo +nightly fuzz fmt profile_parse fuzz/artifacts/profile_parse/crash-XXX
cargo +nightly fuzz tmin profile_parse fuzz/artifacts/profile_parse/crash-XXX
```

`tmin` shrinks the input; `fmt` pretty-prints it for inspection.
