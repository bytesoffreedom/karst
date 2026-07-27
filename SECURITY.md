# Security Policy

## Maturity status

**KARST is a reference implementation. Its cryptography has NOT been
independently audited.** Do not use it to protect real people from a real
adversary. The full map of what is really implemented, what is stubbed, and what
is blocked on an external dependency (the RLN zk-circuit, an audit of the
threshold ring signature) is in [`docs/STATUS.md`](docs/STATUS.md).

Some primitives (§7.3 threshold ring signature) are built as a feature-gated
reference behind `--features unaudited-crypto` and are **off by default**. Do not
enable it outside of tests and research.

## Supported versions

The project is under active development; there are no stable releases yet.
Security fixes land on the `main` branch.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities. Use the private channel:
GitHub → **Security** tab → **Report a vulnerability** (private advisory).

Describe: the affected component (`admission`/`node`/`client`/`gui`), the version
(commit), reproduction steps, and an impact assessment. Responses come as the
maintainer is able; the project is non-commercial and there is no SLA guarantee.

## Threat model (in brief)

Kerckhoffs's principle: the whole protocol, code, and algorithms are open; only
keys, one-time capabilities, and momentary network topology are secret. The threat
model is actor-neutral — a property holds by what an adversary can *do*, not who
they are. The goals include end-to-end content confidentiality, resilient delivery
across independently operated relays, resistance to DoS (proof of the right to spend
resources before any memory is allocated), and resistance to Sybil attacks. For
more, see [`KARST_SPEC.md`](KARST_SPEC.md).

KARST is a private messenger, **not an anonymity system**: it does not guarantee
anonymity, and network/transport metadata may remain visible. Transport privacy and
content confidentiality are **different properties** — a proxy (Tor/VPN/I2P) is a
user-configured network option, not a replacement for application-level metadata
protection. See [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md) for intended use and
[`docs/TECHNICAL_BOUNDARIES.md`](docs/TECHNICAL_BOUNDARIES.md) for the test-backed
boundaries (KARST is not a VPN, proxy, tunnel, or a tool that interferes with filtering
or security equipment); please do not run tests against infrastructure you do not
operate or have permission to test.
