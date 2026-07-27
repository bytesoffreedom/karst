# Responsible Use

## Intended purpose

KARST is intended for lawful private communication, interoperability
research, cryptographic engineering, and testing of independently
operated messaging infrastructure.

## Prohibited and harmful uses

The KARST maintainers do not design, endorse, or promote the project for:

- unauthorized access to computers, accounts, networks, or data;
- malware development or distribution;
- credential theft, phishing, or identity theft;
- denial-of-service attacks or disruption of third-party infrastructure;
- fraud, extortion, blackmail, or financial theft;
- distribution of stolen or unlawfully obtained data;
- stalking, harassment, threats, or doxxing;
- exploitation or sexual abuse of children;
- human trafficking or exploitation;
- planning or facilitating violent crime;
- terrorist or extremist propaganda, recruitment, financing, or operations;
- illegal trade in weapons, drugs, stolen property, or other prohibited goods;
- money laundering or unlawful financial activity;
- interference with security software, network equipment, or third-party systems;
- any other activity prohibited by applicable law.

## Technical boundaries

The official KARST implementation is not intended to operate as:

- a general-purpose VPN;
- an open Internet proxy;
- a Tor exit node;
- an unrestricted TCP or UDP tunnel;
- an exploit framework;
- malware;
- a system for unauthorized access to third-party services.

KARST carries only messages and files belonging to the KARST protocol.

The full, test-backed statement of these boundaries — including no arbitrary
destinations, no unrestricted HTTP CONNECT, and no active interference with filtering
or security equipment — is in [`docs/TECHNICAL_BOUNDARIES.md`](docs/TECHNICAL_BOUNDARIES.md).

## User and operator responsibility

Users are responsible for how they install, configure, and use KARST, and for
complying with the laws applicable to them. Independent relay operators are
responsible for the infrastructure they own or are authorized to administer —
including its security, configuration, retention policy, resource limits, and legal
compliance.

Unless explicitly stated otherwise, publication of the KARST source code does **not**
mean the maintainers operate, control, supervise, or approve:

- independently operated relays;
- modified forks;
- third-party distributions;
- user-generated encrypted content;
- deployments created by unrelated individuals or organizations.

The maintainers cannot monitor, decrypt, approve, or control every independent use,
modification, redistribution, or deployment of open-source software.

## Official infrastructure

Where the KARST maintainers operate an official website, release service, relay,
directory, or other infrastructure, the scope of their control and the data
technically available to that infrastructure is documented separately. This
responsibility statement must **not** be read to deny control over infrastructure the
maintainers actually operate.

## Experimental status

The current implementation is experimental and independently unaudited.
It must not be treated as a guarantee of anonymity, security,
availability, legal compliance, or protection against every adversary.

## No warranty

KARST is an experimental pre-alpha reference implementation. The cryptographic
composition has not completed an independent security audit. The software must not be
relied upon for high-risk communications, or circumstances in which a failure of
confidentiality, integrity, availability, or delivery could endanger a person. To the
maximum extent permitted by applicable law, the software is provided without warranties
of security, anonymity, availability, fitness for a particular purpose, legal
compliance, or compatibility.

## Limitation of liability

To the maximum extent permitted by applicable law, the maintainers and contributors are
not liable merely because a third party independently uses, modifies, redistributes,
misconfigures, or operates the software. Nothing here excludes or limits liability that
cannot lawfully be excluded, including liability arising from a maintainer's own
intentional misconduct where applicable law prohibits such exclusion.

This document describes the intended scope of the official KARST project. It is not a
legal opinion and does not guarantee that KARST or any particular deployment is lawful
in every jurisdiction.
