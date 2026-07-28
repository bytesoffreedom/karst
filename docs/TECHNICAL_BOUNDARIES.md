# Technical Boundaries

This document states the intended technical boundaries of the **official** KARST
implementation: what the software does, and — deliberately — what it does not do.
It complements [`RESPONSIBLE_USE.md`](../RESPONSIBLE_USE.md) (intended use),
[`POSITIONING.md`](POSITIONING.md) (wording), and [`SECURITY_CLAIMS.md`](SECURITY_CLAIMS.md)
(claims matrix).

## Purpose

KARST is an experimental private messaging protocol and reference implementation.
Its purpose is to transmit end-to-end encrypted KARST messages and files between
consenting users through independently operated KARST relays. The official
implementation is designed to reduce the risks of unauthorized access, account
compromise, malicious or compromised infrastructure, contact-key substitution, data
breaches, and long-term collection of encrypted traffic.

## Protocol scope

The KARST client and relay process only operations defined by the KARST protocol:

- publishing authenticated cryptographic key bundles;
- depositing encrypted message envelopes;
- leasing and acknowledging encrypted envelopes;
- storing and retrieving encrypted file chunks;
- exchanging authenticated relay descriptors;
- performing bounded protocol discovery operations.

Unknown or malformed protocol operations are rejected.

## No arbitrary destinations

The KARST relay does not accept user-controlled arbitrary Internet destinations. The
relay protocol has no generic request carrying an unrestricted hostname, IP address,
TCP/UDP port, URL, external network service, or arbitrary bidirectional byte stream.
Users may select which KARST relay their client connects to; a relay does not connect
on the user's behalf to arbitrary third-party services.

## Not a general-purpose VPN

The official KARST implementation does not create a system-wide TUN/TAP interface,
replace the device's default route, capture other applications' traffic, operate a
system-wide DNS tunnel, forward arbitrary IP packets, or provide general Internet
connectivity. KARST transports only KARST protocol messages and files.

## Not an Internet proxy

The official KARST relay does not operate as an HTTP proxy, a general-purpose HTTP
CONNECT proxy, a SOCKS proxy, an unrestricted TCP/UDP forwarder, a Tor exit node, or an
Internet gateway. KARST may connect **through** a user-configured proxy (for example a
local SOCKS proxy); in that case KARST is a proxy *client* for its own connection to a
KARST relay, and provides no proxy service to other applications.

## No unrestricted HTTP CONNECT

KARST does not accept requests instructing a relay to tunnel to an arbitrary
third-party host. Standards-compliant transports may use HTTP or WebSocket mechanisms
only when the connection terminates at the KARST relay and carries only the KARST
protocol.

## No active interference with filtering or security equipment

The official implementation does not attempt to access, modify, disable, damage,
exploit, or reconfigure equipment operated by network providers or other third parties.
It does not intentionally generate malformed or conflicting network packets to
desynchronize traffic-inspection systems. It contains no deliberately invalid
checksums, no overlapping-TCP-segment techniques, no forged reset packets, no
TTL-based fake-packet techniques, no exploitation of filtering-system vulnerabilities,
no scanning for filtering or security equipment, and no attacks against network
infrastructure. KARST uses standard networking interfaces and transports to
communicate with endpoints whose operators have chosen to participate in the protocol.

## No unauthorized access

KARST is not intended or designed to obtain access to computers, accounts, networks,
or data without authorization; bypass authentication protecting third-party systems;
steal credentials; collect third-party information without permission; execute code on
third-party systems; modify or delete third-party information; interfere with endpoint
security software; or install or persist without the device owner's informed consent.

## Consent and user control

Network actions follow the configuration the user selected. The client does not
silently start a public relay, open an inbound listening port, enable system-wide
proxying, change system routing, install a VPN profile, route other applications'
traffic, downgrade from a user-selected proxy route to a direct connection, or connect
to a newly offered relay when that requires explicit approval. Background
synchronization and reconnection occur only after the user has enabled those functions.
Security-sensitive choices remain visible, reversible, and accurately described in the
UI.

## Relay boundaries

A KARST relay **may**: receive authenticated KARST requests; store encrypted envelopes
and file chunks; return encrypted data to an authorized recipient; enforce quotas,
admission controls, and resource limits; publish its own authenticated relay descriptor.

A KARST relay **must not**: interpret encrypted message content as a network
instruction; open connections to destinations supplied inside an encrypted payload;
forward arbitrary streams; expose a general proxy service; provide an Internet exit; or
scan or exploit third-party infrastructure.

## Transport adapters

Transport adapters carry the KARST protocol between a KARST client and a KARST relay,
using standard technologies (TCP, TLS, WebSocket, or a user-configured proxy). They do
not turn KARST into a general-purpose VPN or Internet proxy. Using a transport adapter
does not guarantee anonymity, traffic indistinguishability, universal connectivity, or
protection against every network observer.

## Independent relay operators

KARST relays may be operated independently. An independent operator is responsible for
systems they own or are authorized to administer, and for compliance with the laws that
apply to their operation. Unless explicitly stated, an independent relay operator is not
an agent, employee, or representative of the KARST maintainers.

## Contributions

The following are outside the scope of the official implementation: unrestricted
Internet proxying; arbitrary TCP/UDP/HTTP/SOCKS/IP tunnelling; an Internet exit service;
unauthorized-access functionality; malware installation or persistence; credential
theft; exploitation of third-party infrastructure; active attacks against filtering or
security systems; hidden modification of system-wide networking; or functionality
intended primarily to disrupt third-party systems. Security-research code must be
clearly isolated, documented, disabled by default where appropriate, and must not target
infrastructure without authorization. See [`../README.md`](../README.md) (Contributing)
and [`../SECURITY.md`](../SECURITY.md).

## Verification

These boundaries are backed by code review and automated tests. Representative existing
tests (run `cargo test` / `cargo test --features unaudited-crypto`):

- **Protected transport policy does not silently downgrade** — `socks5_dead_proxy_hard_fails_no_direct` (`impl/node/tests/socks5.rs`), `isolation_fails_closed_when_the_proxy_will_not_isolate`, and the carrier allowlist `filter_allowed_drops_a_live_direct_path_for_a_wss_user` (`impl/client`).
- **Unknown / malformed frames are rejected before allocation** — `garbage_body_rejected`, `oversized_length_rejected_without_alloc`, `malformed_kem_ciphertext_length_rejected`, `oversize_chunk_is_rejected_before_store`.
- **Relay mode requires explicit configuration (fails closed)** — `role_parse_fails_closed_on_an_unknown_mode` (`impl/node/src/bin/relay.rs`).
- **Admission rejects unauthorized requests** — `without_a_pow_issuer_an_unknown_id_is_rejected`, `bad_capability_rejected_regardless_of_content`; the relay authenticates via `verify_accepts_real_relay_and_rejects_impostors`.
- **Resource limits reject instead of silently losing/growing** — `mailbox_cap_rejects_instead_of_silent_loss`.

Design facts (no dedicated test because the capability simply does not exist in the
code): the wire protocol has **no** unrestricted-destination field; the standard client
creates **no** system-wide network interface and changes **no** system routing; a relay
opens **no** outbound connection from a user-supplied arbitrary destination.

Known verification gaps to close (tracked): an explicit discriminating test that a
relay port **rejects a raw HTTP-proxy / SOCKS greeting** (today a non-Noise handshake
simply fails, but this is asserted only indirectly).

## Limitations

This document describes intended technical boundaries of the official implementation.
It is not a legal opinion, does not guarantee legality in every jurisdiction, and does
not control independently modified forks. The implementation is experimental and has not
completed an independent security audit.
