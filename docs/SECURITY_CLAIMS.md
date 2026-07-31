# Security claims matrix

This is the single source of truth for what KARST claims. **No README, website,
social profile, or announcement may state a property more strongly than this
table.** When code and this table disagree, the code is authoritative and this
table must be corrected.

All cryptographic properties below are provided by an **experimental,
independently unaudited** reference implementation.

| Claim                               | Status                 | Limitations                                      |
| ----------------------------------- | ---------------------- | ------------------------------------------------ |
| End-to-end content encryption       | Implemented, unaudited | Does not hide all metadata                       |
| Hybrid post-quantum key agreement   | Implemented, unaudited | No independent cryptographic audit               |
| Safety number verification          | Implemented            | Requires out-of-band comparison                  |
| Independent relay operation         | Implemented            | Relay availability is not guaranteed             |
| Multi-relay delivery                | Implemented/partial    | Depends on client configuration                  |
| Encryption at rest                  | Implemented            | Depends on password strength and device state    |
| Routing through an external anonymity network (Tor / I2P / Nym mixnet) | Implemented/partial | The seam is ours, the anonymity is theirs: KARST dials a SOCKS bridge the user configures and never switches to a carrier that loses a property the user chose. Requires that network to be installed, reachable and trusted; the relay still sees a connection |
| A relay's retention posture is readable before you connect to it | Implemented/partial | The posture (blob persistence and TTL, mailbox durability, door policy) travels inside the relay's own signed descriptor, so a client filters on it without contacting the relay. It is an operator CLAIM the signature makes accountable, not a proof; and it does not cover the FIRST relay, where a client has only a configured address and must connect to learn anything |
| A remote check that a relay keeps no logs | Not claimed | The reference relay's request path contains no logging statement, and a source guard fails the build if one appears — but that is a property of THIS software, not of whatever binary an independent operator is running. Nothing observable from outside distinguishes the two, so no field advertises it: a "we do not log" flag would read as a guarantee while being unverifiable |
| Sender anonymity                    | Not claimed            | Network and relay metadata may remain visible    |
| Traffic indistinguishability        | Not claimed            | Statistical classification may be possible       |
| Universal connectivity              | Not claimed            | Paths and endpoints may become unavailable       |
| Protection from all quantum attacks | Not claimed            | Experimental hybrid construction                 |
| Guaranteed message delivery         | Not claimed            | Availability depends on reachable infrastructure |
| General-purpose VPN / Internet proxy | Not offered by design  | Carries only KARST protocol traffic — see [`TECHNICAL_BOUNDARIES.md`](TECHNICAL_BOUNDARIES.md) |
| Arbitrary TCP/UDP tunnel or Tor exit | Not offered by design  | The relay opens no user-directed outbound connections |
| Interference with filtering/security equipment | Not offered by design | No packet desync, exploitation, or scanning; standard networking only |

## How to read this table

- **Implemented** — present and working in the reference implementation.
- **Implemented, unaudited** — present, but the cryptographic composition has not
  had an independent audit.
- **Implemented/partial** — works, but only under specific configuration or with
  known gaps (see [`STATUS.md`](STATUS.md)).
- **Not claimed** — KARST does **not** assert this property. Do not describe it as
  a feature anywhere.
- **Not offered by design** — a capability the official implementation deliberately
  does **not** provide (a technical boundary, see
  [`TECHNICAL_BOUNDARIES.md`](TECHNICAL_BOUNDARIES.md)). Never describe it as a feature
  or a roadmap item.

For the line-by-line maturity of every mechanism, see [`STATUS.md`](STATUS.md).
For positioning rules and approved wording, see [`POSITIONING.md`](POSITIONING.md).
