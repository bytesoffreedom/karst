# Contributing to KARST

Thanks for your interest. KARST is an **experimental, pre-alpha reference
implementation** of a private messenger with end-to-end encryption and hybrid
post-quantum key agreement. Its cryptographic composition has **not** been
independently audited — see [SECURITY.md](SECURITY.md) and
[docs/STATUS.md](docs/STATUS.md) for what is really implemented, what is stubbed,
and what is blocked on an external dependency.

## Ground rules

- **Security issues are never public.** Do not open a public issue for a
  vulnerability — use the private channel in [SECURITY.md](SECURITY.md)
  (GitHub → **Security** → **Report a vulnerability**).
- **Positioning.** KARST is described in actor-neutral terms: it defends against
  what a malicious actor can *do* — interception, tampering, impersonation,
  compromised infrastructure — not against any particular group. Keep wording in
  docs, comments, and UI aligned with [docs/POSITIONING.md](docs/POSITIONING.md),
  and never claim more than [docs/SECURITY_CLAIMS.md](docs/SECURITY_CLAIMS.md)
  allows (no "unbreakable", "quantum-proof", or "fully anonymous").
- **Discuss first.** For anything non-trivial, open an issue before a large PR.

## Building and testing

The Rust workspace lives under `impl/`:

```sh
cd impl
cargo build
cargo test                                # default suite
cargo test --features unaudited-crypto    # + feature-gated reference crypto
cargo clippy --all-targets
```

Run a local relay and clients following [docs/RUNNING.md](docs/RUNNING.md).

## Conventions

- **Language:** English for code, comments, commit messages, and documentation.
- **Commits:** imperative subject lines; explain *why* in the body.
- **Focus:** one logical change per pull request.
- **Tests:** add or update tests for behavioral changes and keep the suite green.

## License

By contributing, you agree that your contributions are licensed under the
repository's [LICENSE](LICENSE) (GNU AGPL-3.0-or-later).
