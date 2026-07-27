# KARST — reference implementation of the admission protocol (§7)

The first executable slice of the `../KARST_SPEC.md` specification. Its scope is
only the cryptographic admission path (§7.1–7.6): the most concretely specified
and most crypto-heavy piece, and therefore the first place where a prose audit
structurally could not verify that the primitives (Privacy Pass + threshold ring
signature + RLN) actually **compose** on a real crypto library.

> The single map of "what is real / what is stubbed / what is blocked on an
> external dependency" is [`../docs/STATUS.md`](../docs/STATUS.md).
>
> **To run the whole system locally** (relay + two clients, GUI or CLI), see
> [`../docs/RUNNING.md`](../docs/RUNNING.md). Quick check: `scripts/karst-demo.sh`.

## What is implemented "for real"

| Module          | §    | Status |
|-----------------|------|--------|
| `params`        | 7.0  | protocol parameters |
| `cookie`        | 7.1  | stateless cookie, HMAC-SHA256, 2-key rotation, constant-time comparison |
| `capability`    | 7.2  | symmetric HMAC capability + proof, scope/expiry check |
| `rln`           | 7.4  | **core** nullifier + Shamir slashing over the Curve25519 scalar field + `RlnQuotaTracker` (double-spend detection → deanonymization of a quota violator) |
| `pipeline`      | 7.5/7.6 | orchestrator of stages 0–5 + a bounded replay filter |
| `dtn`           | 7.7  | DTN admission class for the offline mesh: HMAC capability without an epoch, per-peer + device-wide carry budget (Sybil defense), rolling-window replay |

## Boundaries, stated honestly (not hidden behind prose)

- **§7.3 threshold ring signature** — implemented as a **feature-gated
  reference that has NOT been audited** (`--features unaudited-crypto`, off by
  default). See the `tring` module.

  A survey of the ecosystem (not a hypothesis): there is no off-the-shelf t-of-N
  anonymous threshold ring signature in Rust or anywhere in production; all ring
  crates are 1-of-N (Monero), FROST is threshold but not anonymous and requires a
  DKG, and Bresson–Stern–Szydlo itself is built on RSA and does NOT compose with
  Curve25519. So instead of literal BSS we implement a **CDS construction**
  (Cramer–Damgård–Schoenmakers, CRYPTO 1994): a threshold σ-composition of
  Schnorr proofs over Ristretto255 via Shamir-splitting the challenge, with
  Fiat–Shamir. Discrete-log, compatible with the Ed25519 stack.

  The "not for production" status is kept deliberately: "more reliable" for
  security crypto ultimately means an independent audit, which we don't have. The
  weight is carried by adversarial tests (`tests/tring_adversarial.rs`, 15 of
  them): `<t` signers → reject; `≥t` → pass; a mangled signature → reject;
  swapping the message/ring/order → reject; rebinding the nonce to the ring
  (defense against an RLN-class leak). Composition with the §7.5 pipeline is
  proven in `tests/tring_pipeline.rs`. Until an audit, the main §7.3 path stays
  `AdmissionTokenVerifier` (a trait) + `MockRingVerifier`; `RealRingVerifier` is
  enabled by the feature. See §7.3 of the specification.
- **§7.4 RLN zk_proof wrapper** — requires a circom/halo2 circuit, not
  off-the-shelf. The field core (detection + slashing) and a working
  `RlnQuotaTracker` are implemented (per-epoch nullifier accounting; a second
  different message from one identity → `slash()` → `QuotaViolation` with the
  recovered secret, test `second_different_message_deanonymizes_violator`).
  **Boundary:** the tracker ASSUMES zk-verified shares — without the zk membership
  wrapper (`ZkProofStub`) it is a punishment layer ON TOP of verification, not a
  full admission gate; so the RLN branch in the pipeline stays `RlnNotImplemented`.
  The limit is 1 message/epoch (a degree-1 core); limits > 1 require a polynomial
  of degree `limit`, which the core does not have.
- **Poseidon → SHA-512** in `rln`: the verifiable property (recovering the secret
  from two shares) is purely field-based and does not depend on the choice of
  hash; Poseidon is needed only for cheapness INSIDE a zk circuit, which is not
  here.

## A finding the implementation surfaced

`§7.4`: the spec left the slope `a0` undefined, while its `nullifier` formula is
the standard RLN formula for the *slope*. With the standard derivation
`a0 = H(secret‖ext)`, the slope would coincide with the public `nullifier` → a
single share would leak the secret (deanonymization on the first message, not on a
repeat). Fixed in the spec and the code: `nullifier = H(a0)`, not `a0`. The
necessary condition (`nullifier ≠ slope`) is pinned by the test
`nullifier_is_not_the_slope`; sufficiency rests on the preimage resistance of the
hash.

## Conformance vectors

`admission/tests/vectors.json` is a frozen artifact. The test
`conformance_vectors_match_frozen` compares the computed bytes against
hardcoded constants and **fails on any drift** (a different `hash_to_field`, MAC,
serialization) — it does not recompute the "right" answer on the fly. A second
implementation must reproduce exactly these bytes. To update the artifact
deliberately: `KARST_REGEN_VECTORS=1 cargo test`.

## DTN admission class (§7.7)

A path separate from the live class for the offline mesh (Bluetooth/Wi-Fi
Direct), central to resilience against a full network shutdown. The load-bearing
test is `device_budget_caps_sybil_of_many_cheap_identities`: 100 ephemeral mesh
identities, each under a per-peer limit, hit the aggregate device budget (exactly
the §7.7 Sybil argument — cheap Bluetooth identities cannot be held back by a
single per-peer ceiling). `max_hops` is honestly left advisory
(cryptographically unenforceable in an opportunistic mesh).

**Integration into the Ingress pipeline** (`process_dtn`, §10): a single Ingress
branches by credential type at Stages 3–4 (not a separate gateway). Two integrity
subtleties that surfaced during implementation (a DTN proof travels through
untrusted mesh carriers), with tests in `tests/dtn_pipeline.rs`:
- the single capsule id = `H(ciphertext)` serves as both the MAC input and the
  rolling-window key → a proof stolen from the mesh cannot be attached to other
  content (`proof_cannot_be_reattached_to_other_content`);
- insertion into the rolling window happens only AFTER the HMAC (Stage 3 is a
  read-only CHECK) → a garbage proof uploaded first does not burn the id of a real
  capsule (`garbage_proof_does_not_burn_capsule_id`).

## Build and tests

```sh
cargo test          # 11 tests, including the load-bearing slashing property
cargo clippy --all-targets
```

`cargo test` also rewrites `admission/tests/vectors.json` — deterministic,
language-agnostic test vectors for conformance of independent implementations
(§14 requires that they exist).
