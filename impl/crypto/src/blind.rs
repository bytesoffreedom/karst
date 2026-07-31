//! **Wired into the live drop-box path (reference construction — the Schnorr fetch proof is
//! unaudited).** Mailbox deposit/fetch key separation via per-epoch point-blinding (the Tor v3
//! key-blinding pattern). Established sessions deposit into and fetch from a blinded box
//! (`peer.rs` → `deposit_address` / `FetchOwnershipProof`, gated by `node::mailbox_owner_ok`);
//! first-contact openers and the self loop-box still use the identity mailbox + DH proof.
//!
//! # The gap this closes (see docs/design/mailbox-fetch-key-separation.md)
//!
//! Without this, both parties derive the FULL mailbox keypair per direction from the shared
//! `drop_seed` (`crate::drop`), so a sender can also derive the recipient's *fetch* secret —
//! "can deposit" implicitly confers "can read" (still the case for the identity mailbox used by
//! first-contact openers, bounded to two-party defence-in-depth: each side only reaches a box
//! holding data it is already party to). This module breaks that for established sessions, and
//! is the construction that also generalizes when the bound must break further (group mailboxes,
//! deposit delegation).
//!
//! # The construction
//!
//! The recipient holds an INDEPENDENT per-session secret scalar `m` (NOT derived from the
//! root key — deriving it would let the sender recompute it and the separation would
//! collapse) and publishes only `M = m·G`. Per epoch/direction a public blinding scalar
//! `h = H(root_key, epoch, dir)` is derivable by both sides from the shared root key. Then:
//!
//! - **deposit address** `= h·M = (h·m)·G` — the SENDER computes it from the public `M` and
//!   `h`. It is a public key; the sender learns only where to deposit.
//! - **fetch secret** `= h·m` — only the holder of `m` computes it, and its public key is
//!   exactly the deposit address. So only the recipient can prove ownership of the box.
//!
//! A sender would need the discrete log of `M` (i.e. `m`) to get the fetch secret, which it
//! does not have. Deposit no longer implies fetch.
//!
//! # Why Ristretto (not raw X25519 / Edwards)
//!
//! Multiplicative blinding needs clean scalar arithmetic in a PRIME-ORDER group.
//! `x25519-dalek` clamps scalars and exposes no scalar mul, so `pub_of(h·m) ≠ h·(m·G)` — the
//! construction is not even expressible there (the landmine that deferred it). Ristretto255
//! is prime-order, so there is no cofactor to leak and `h·(m·G) = (h·m)·G` holds exactly.
//!
//! # The relay-side ownership proof — BUILT AND WIRED (reference, unaudited)
//!
//! The identity mailbox is gated by `fetch_proof = DH(mailbox_secret, relay_x25519_identity)`
//! — a DH against the relay's X25519 Noise key. A Ristretto fetch secret shares no DH with an
//! X25519 key, so a blinded box is gated instead by an in-group proof: a Schnorr proof of
//! knowledge of `fetch_secret` (the discrete log of the deposit address), verified by the relay
//! in the Ristretto group (`FetchOwnershipProof`, checked in `node::mailbox_owner_ok`, shared by
//! `handle_fetch`/`handle_ack`; the client builds it in `peer.rs`). This is a SECOND primitive,
//! un-CI-able the same way a signature is (a broken construction verifies against itself) and
//! **UNAUDITED** — it wants a vetted construction + known-answer vectors before any production
//! claim, the same discipline as the XEdDSA prekey signature.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use sha2::Sha512;

/// The recipient's per-session mailbox secret `m`. **Independent random scalar** — must NOT be
/// derived from the session root key, or a sender who also holds the root key could recompute
/// it and the separation would be void.
pub struct MailboxSecret(Scalar);

impl MailboxSecret {
    /// A fresh independent secret from the OS CSPRNG (wide-reduced to a uniform scalar).
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        MailboxSecret(Scalar::from_bytes_mod_order_wide(&wide))
    }

    /// Reconstruct from the stored 32-byte secret (persistence; canonical scalars only).
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Option::<Scalar>::from(Scalar::from_canonical_bytes(*bytes)).map(MailboxSecret)
    }

    /// DETERMINISTICALLY derive the mailbox secret from an account's own secret material (its
    /// seed-derived key bytes), domain-separated + wide-reduced to a uniform scalar. This keeps
    /// `m` PER-ACCOUNT and re-derivable from the seed (no separate persistence), and — crucially —
    /// derived from the RECIPIENT's private material, which a sender never holds, so the sender
    /// still cannot recompute it. (The only forbidden source is the shared SESSION root key.)
    pub fn derive(account_secret: &[u8]) -> Self {
        let mut input = Vec::with_capacity(24 + account_secret.len());
        input.extend_from_slice(b"KARST-mailbox-secret-v1");
        input.extend_from_slice(account_secret);
        MailboxSecret(Scalar::hash_from_bytes::<Sha512>(&input))
    }

    /// The 32-byte secret, to persist (a private key — same care as the ratchet).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The PUBLIC mailbox point `M = m·G`, published so a sender can derive deposit addresses.
    pub fn public(&self) -> [u8; 32] {
        (&self.0 * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes()
    }

    /// The fetch secret `h·m` for one epoch/direction/relay — only the holder of `m` can compute
    /// it. Its public key is exactly the sender's deposit address for that box AT THAT RELAY.
    pub fn fetch_secret(
        &self,
        root_key: &[u8; 32],
        epoch: u64,
        dir: u8,
        relay_id: &[u8; 32],
    ) -> [u8; 32] {
        (blind_factor(root_key, epoch, dir, relay_id) * self.0).to_bytes()
    }
}

/// The blinding scalar `h = H(domain ‖ root_key ‖ epoch ‖ dir ‖ relay_id)`, wide-reduced to a
/// UNIFORM scalar (never `from_bytes_mod_order` on 32 bytes, which biases).
///
/// `dir` is bound so the A→B and B→A boxes of a session differ.
///
/// **`relay_id` is bound so the SAME box has a DIFFERENT address at every relay** (PRIV-12). Without
/// it, the address was a function of the session alone, so a client that multi-homes polled the
/// identical 32 bytes at relay A and relay B — and two colluding relays could join their logs on an
/// EXACT MATCH rather than on timing or volume. That is the cheapest possible join, and it made
/// multi-homing (added for availability) quietly buy cross-relay linkability. It is a different axis
/// from the one PRIV-4 closes: re-wrapping the ciphertext per relay leaves the address identical.
///
/// This costs nothing to derive on either side. The sender knows which relay it is depositing to and
/// the recipient knows which relay it is polling, so both compute the same scalar for that relay
/// without exchanging anything — and the number of polls is unchanged, because a recipient already
/// walks its boxes once per relay.
///
/// Which 32 bytes: the relay's Noise static public key. It is the value the client PINS and the
/// handshake authenticates, so a relay cannot induce a client to derive some other relay's address
/// by lying about its identity — it would fail the handshake first.
pub fn blind_factor(root_key: &[u8; 32], epoch: u64, dir: u8, relay_id: &[u8; 32]) -> Scalar {
    let mut input = Vec::with_capacity(22 + 32 + 8 + 1 + 32);
    input.extend_from_slice(b"KARST-mailbox-blind-v2");
    input.extend_from_slice(root_key);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.push(dir);
    input.extend_from_slice(relay_id);
    Scalar::hash_from_bytes::<Sha512>(&input)
}

/// The deposit ADDRESS `h·M` for one epoch/direction — computed by the SENDER from the public
/// mailbox point `M` and the shared `root_key`, with NO access to `m`. `None` if `M` is not a
/// valid Ristretto point. Equal to the public key of the recipient's `fetch_secret`.
pub fn deposit_address(
    m_pub: &[u8; 32],
    root_key: &[u8; 32],
    epoch: u64,
    dir: u8,
    relay_id: &[u8; 32],
) -> Option<[u8; 32]> {
    let m_point = CompressedRistretto(*m_pub).decompress()?;
    Some((blind_factor(root_key, epoch, dir, relay_id) * m_point).compress().to_bytes())
}

/// The public key of a fetch secret, `s·G` — so a test (and, later, the relay's ownership
/// proof) can check it equals the deposit address.
pub fn public_of_secret(secret: &[u8; 32]) -> Option<[u8; 32]> {
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*secret))?;
    Some((&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes())
}

/// The relay-side ownership proof for a blinded mailbox — **wired into the live fetch/ack gate
/// (`node::mailbox_owner_ok`).** The identity mailbox is gated by
/// `DH(mailbox_secret, relay_x25519_identity)`; a Ristretto fetch secret shares no DH with the
/// relay's X25519 key, so a blinded mailbox is gated by this in-group ownership proof instead: a
/// Schnorr proof of knowledge of the fetch secret `s` — the discrete log of the deposit address
/// `P = s·G` — that the relay verifies to grant a fetch, without ever learning `s`.
///
/// **REFERENCE / UNAUDITED — un-CI-able the way a signature is** (a broken construction verifies
/// against itself). Before any production claim it needs a vetted construction + known-answer
/// vectors, the same discipline as the XEdDSA prekey signature. What the tests below CAN pin: a valid proof
/// verifies; a wrong secret / a tampered proof / a wrong context / a wrong statement do not.
///
/// Fiat–Shamir Schnorr over Ristretto255:
/// - commitment `R = r·G`, `r` a fresh UNIFORM scalar (wide-reduced from 64 random bytes — never
///   `from_bytes_mod_order` on 32, which biases and would leak);
/// - challenge `c = H(domain ‖ P ‖ R ‖ context)` — binds the STATEMENT `P` (else a proof
///   transfers to another box) AND the `context` (a relay-supplied challenge; else it replays);
/// - response `z = r + c·s`; verify `z·G == R + c·P`.
pub struct FetchOwnershipProof {
    r_pub: [u8; 32],
    z: [u8; 32],
}

/// The Fiat–Shamir challenge scalar, wide-reduced to uniform. Binds the statement (deposit
/// address), the commitment, and the relay-supplied context.
fn fetch_challenge(deposit_address: &[u8; 32], r_pub: &[u8; 32], context: &[u8]) -> Scalar {
    let mut input = Vec::with_capacity(28 + 32 + 32 + context.len());
    input.extend_from_slice(b"KARST-mailbox-fetch-proof-v1");
    input.extend_from_slice(deposit_address);
    input.extend_from_slice(r_pub);
    input.extend_from_slice(context);
    Scalar::hash_from_bytes::<Sha512>(&input)
}

impl FetchOwnershipProof {
    /// Prove knowledge of the fetch secret `s` for the box at `deposit_address` (`= s·G`), bound
    /// to `context`. `s` must be the discrete log of the deposit address — i.e. the recipient's
    /// `MailboxSecret::fetch_secret` for that epoch/direction. `None` on a non-canonical secret.
    pub fn prove(fetch_secret: &[u8; 32], deposit_address: &[u8; 32], context: &[u8]) -> Option<Self> {
        use rand::RngCore;
        let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(*fetch_secret))?;
        let mut wide = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut wide);
        let r = Scalar::from_bytes_mod_order_wide(&wide);
        let r_pub = (&r * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
        let c = fetch_challenge(deposit_address, &r_pub, context);
        let z = (r + c * s).to_bytes();
        Some(FetchOwnershipProof { r_pub, z })
    }

    /// Verify the proof against the PUBLIC deposit address + the same context. `false` on any
    /// malformed input (non-canonical scalar, invalid or identity point) or a failed check. This
    /// is what a relay would run to gate a fetch — it never sees the secret.
    pub fn verify(&self, deposit_address: &[u8; 32], context: &[u8]) -> bool {
        use curve25519_dalek::traits::IsIdentity;
        let Some(p) = CompressedRistretto(*deposit_address).decompress() else { return false };
        if p.is_identity() {
            return false; // a box at the identity has a trivial discrete log — reject
        }
        let Some(r) = CompressedRistretto(self.r_pub).decompress() else { return false };
        let Some(z) = Option::<Scalar>::from(Scalar::from_canonical_bytes(self.z)) else {
            return false;
        };
        let c = fetch_challenge(deposit_address, &self.r_pub, context);
        (&z * RISTRETTO_BASEPOINT_TABLE) == r + c * p
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.r_pub);
        out[32..].copy_from_slice(&self.z);
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r_pub = [0u8; 32];
        let mut z = [0u8; 32];
        r_pub.copy_from_slice(&bytes[..32]);
        z.copy_from_slice(&bytes[32..]);
        FetchOwnershipProof { r_pub, z }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in relay identity: the address is relay-specific now (PRIV-12), so every derivation
    /// in these tests names one.
    const RELAY: [u8; 32] = [0xA7; 32];
    const RK: [u8; 32] = [7u8; 32];

    /// The defining property: the SENDER (holding only the public `M` + the shared root key)
    /// derives the same deposit address the RECIPIENT's fetch secret unlocks — without ever
    /// touching `m`. deposit = h·M = (h·m)·G = fetch_secret·G.
    #[test]
    fn sender_derives_the_address_the_recipients_fetch_secret_unlocks() {
        let m = MailboxSecret::generate();
        let m_pub = m.public();

        // Sender side: only the public M + root key.
        let addr = deposit_address(&m_pub, &RK, 5, 0, &RELAY).expect("valid M");
        // Recipient side: the fetch secret and its public key.
        let secret = m.fetch_secret(&RK, 5, 0, &RELAY);
        assert_eq!(public_of_secret(&secret).unwrap(), addr, "fetch secret unlocks the deposit box");
    }

    /// The fetch secret genuinely needs `m`: a party with the SAME public inputs (M, root key,
    /// epoch, dir) but a DIFFERENT `m` gets a different secret. The sender cannot produce the
    /// fetch secret from `M` alone (that is the discrete-log assumption; here we pin that the
    /// secret is a function of `m`, not just of the public address).
    #[test]
    fn the_fetch_secret_requires_the_private_m() {
        let a = MailboxSecret::generate();
        let b = MailboxSecret::generate();
        assert_ne!(a.fetch_secret(&RK, 5, 0, &RELAY), b.fetch_secret(&RK, 5, 0, &RELAY), "secret is bound to m");
        // Both are valid box secrets for THEIR OWN M — but a sender who saw only a.public()
        // has no route to a.fetch_secret without a's m.
        assert_eq!(public_of_secret(&a.fetch_secret(&RK, 5, 0, &RELAY)).unwrap(), deposit_address(&a.public(), &RK, 5, 0, &RELAY).unwrap());
    }

    /// The address rotates per epoch (so a relay can't chain one address across time) and per
    /// direction (A→B ≠ B→A), exactly like the current drop-box scheme it would replace.
    #[test]
    fn addresses_rotate_by_epoch_and_direction() {
        let m = MailboxSecret::generate();
        let mp = m.public();
        let e5 = deposit_address(&mp, &RK, 5, 0, &RELAY).unwrap();
        let e6 = deposit_address(&mp, &RK, 6, 0, &RELAY).unwrap();
        let e5_rev = deposit_address(&mp, &RK, 5, 1, &RELAY).unwrap();
        assert_ne!(e5, e6, "different epoch → different box");
        assert_ne!(e5, e5_rev, "different direction → different box");
    }

    /// The secret round-trips through persistence bytes.
    #[test]
    fn mailbox_secret_round_trips() {
        let m = MailboxSecret::generate();
        let restored = MailboxSecret::from_bytes(&m.to_bytes()).unwrap();
        assert_eq!(m.public(), restored.public());
        assert_eq!(m.fetch_secret(&RK, 1, 0, &RELAY), restored.fetch_secret(&RK, 1, 0, &RELAY));
    }

    // --- the relay-side ownership proof (Schnorr PoK of the fetch secret) ---

    /// A box for a fresh recipient at (epoch, dir): its public deposit address (what the relay
    /// sees) and the fetch secret (what only the recipient holds).
    fn a_box(epoch: u64, dir: u8) -> ([u8; 32], [u8; 32]) {
        let m = MailboxSecret::generate();
        (deposit_address(&m.public(), &RK, epoch, dir, &RELAY).unwrap(), m.fetch_secret(&RK, epoch, dir, &RELAY))
    }

    /// The defining property: the holder of the fetch secret proves ownership of the box, and the
    /// relay verifies against ONLY the public deposit address + the challenge — never the secret.
    #[test]
    fn a_recipient_proves_ownership_of_its_box() {
        let (addr, secret) = a_box(5, 0);
        let ctx = b"relay-nonce-abc";
        let proof = FetchOwnershipProof::prove(&secret, &addr, ctx).unwrap();
        assert!(proof.verify(&addr, ctx), "the real secret proves ownership");
    }

    /// Soundness: a party WITHOUT the box's fetch secret cannot produce a proof that verifies —
    /// a proof made with a different secret fails against the real deposit address.
    #[test]
    fn a_wrong_secret_cannot_prove_ownership() {
        let (addr, _secret) = a_box(5, 0);
        let (_other_addr, wrong_secret) = a_box(5, 0); // a different box's secret
        let ctx = b"relay-nonce-abc";
        let forged = FetchOwnershipProof::prove(&wrong_secret, &addr, ctx).unwrap();
        assert!(!forged.verify(&addr, ctx), "a proof made without the box's secret must fail");
    }

    /// A tampered proof (either component flipped) is rejected.
    #[test]
    fn a_tampered_proof_is_rejected() {
        let (addr, secret) = a_box(7, 1);
        let ctx = b"ctx";
        let good = FetchOwnershipProof::prove(&secret, &addr, ctx).unwrap();
        let mut b = good.to_bytes();
        b[0] ^= 1; // flip a bit of R
        assert!(!FetchOwnershipProof::from_bytes(&b).verify(&addr, ctx), "tampered R rejected");
        let mut b2 = good.to_bytes();
        b2[40] ^= 1; // flip a bit of z
        assert!(!FetchOwnershipProof::from_bytes(&b2).verify(&addr, ctx), "tampered z rejected");
    }

    /// The context binds the proof: a proof made for one relay challenge does not verify under a
    /// different one — so a captured fetch proof cannot be replayed against another challenge.
    #[test]
    fn the_context_binds_the_proof() {
        let (addr, secret) = a_box(3, 0);
        let proof = FetchOwnershipProof::prove(&secret, &addr, b"challenge-A").unwrap();
        assert!(proof.verify(&addr, b"challenge-A"));
        assert!(!proof.verify(&addr, b"challenge-B"), "a proof does not replay under a new context");
    }

    /// The statement binds the proof: a proof for one box does not transfer to a different box's
    /// address, even with the same context.
    #[test]
    fn the_statement_binds_the_proof() {
        let (addr1, secret1) = a_box(4, 0);
        let (addr2, _secret2) = a_box(9, 1);
        let ctx = b"same-ctx";
        let proof = FetchOwnershipProof::prove(&secret1, &addr1, ctx).unwrap();
        assert!(proof.verify(&addr1, ctx));
        assert!(!proof.verify(&addr2, ctx), "a proof for box 1 does not verify for box 2");
    }

    /// Malformed inputs are rejected: the identity as a deposit address (trivial discrete log),
    /// and a non-canonical response scalar.
    #[test]
    fn identity_and_noncanonical_are_rejected() {
        let (addr, secret) = a_box(1, 0);
        let ctx = b"x";
        // Identity deposit address (all-zero Ristretto encoding) — must never verify.
        let proof = FetchOwnershipProof::prove(&secret, &[0u8; 32], ctx);
        // prove() may still build a proof, but verify against the identity rejects.
        if let Some(pr) = proof {
            assert!(!pr.verify(&[0u8; 32], ctx), "identity box address rejected");
        }
        // A non-canonical response scalar (bytes ≥ group order) is rejected on parse.
        let good = FetchOwnershipProof::prove(&secret, &addr, ctx).unwrap();
        let mut b = good.to_bytes();
        b[32..].copy_from_slice(&[0xFFu8; 32]); // non-canonical z
        assert!(!FetchOwnershipProof::from_bytes(&b).verify(&addr, ctx), "non-canonical z rejected");
    }

    /// The proof round-trips through its 64-byte wire form.
    #[test]
    fn proof_round_trips_bytes() {
        let (addr, secret) = a_box(2, 0);
        let ctx = b"ctx";
        let proof = FetchOwnershipProof::prove(&secret, &addr, ctx).unwrap();
        assert!(FetchOwnershipProof::from_bytes(&proof.to_bytes()).verify(&addr, ctx));
    }
}

/// **The same box has a different address at every relay** (PRIV-12).
///
/// The property exists for one adversary: two relays that compare notes. Everything else about a
/// drop-box already frustrates them — the address is blinded, it rotates per epoch, and it reveals
/// no identity — but until `relay_id` entered the derivation the address was a function of the
/// SESSION alone, so a client that multi-homes polled the identical 32 bytes at both. Colluding
/// relays could then join their logs on an exact match, which is cheaper than any timing or volume
/// correlation and needs no analysis at all.
///
/// Kept as its own module because the fix is invisible in behaviour: delivery works identically
/// either way, so nothing else in the suite notices if this is undone.
#[cfg(test)]
mod an_address_is_specific_to_its_relay {
    use super::*;

    const RK: [u8; 32] = [9u8; 32];

    /// DISCRIMINATING: drop `relay_id` from `blind_factor`'s input and this goes red.
    #[test]
    fn two_relays_never_see_the_same_box_address() {
        let m = MailboxSecret::generate();
        let a = deposit_address(&m.public(), &RK, 5, 0, &[0xA1; 32]).expect("valid M");
        let b = deposit_address(&m.public(), &RK, 5, 0, &[0xB2; 32]).expect("valid M");
        assert_ne!(
            a, b,
            "one session's box has the SAME address at two relays. Two relays that compare logs \
             then join on an exact 32-byte match — the cheapest possible correlation — and \
             multi-homing, which exists for availability, silently buys cross-relay linkability."
        );
    }

    /// The fetch secret must move with the address, or the recipient cannot prove ownership of the
    /// box the sender actually deposited into — delivery would break at the relay's proof check.
    #[test]
    fn the_fetch_secret_matches_its_own_relays_address_and_no_other() {
        let m = MailboxSecret::generate();
        let (r1, r2) = ([0xA1u8; 32], [0xB2u8; 32]);
        let addr1 = deposit_address(&m.public(), &RK, 7, 1, &r1).expect("valid M");
        let addr2 = deposit_address(&m.public(), &RK, 7, 1, &r2).expect("valid M");
        assert_eq!(
            public_of_secret(&m.fetch_secret(&RK, 7, 1, &r1)).expect("canonical"),
            addr1,
            "the fetch secret no longer opens its own relay's box — deposits would be unreachable"
        );
        assert_ne!(
            public_of_secret(&m.fetch_secret(&RK, 7, 1, &r1)).expect("canonical"),
            addr2,
            "one relay's fetch secret matches ANOTHER relay's address, so the separation is cosmetic"
        );
    }

    /// The other axes still separate — the new input must not have swallowed them.
    #[test]
    fn epoch_and_direction_still_separate_within_one_relay() {
        let m = MailboxSecret::generate();
        let r = [0xA1u8; 32];
        let e5 = deposit_address(&m.public(), &RK, 5, 0, &r).expect("valid M");
        let e6 = deposit_address(&m.public(), &RK, 6, 0, &r).expect("valid M");
        let rev = deposit_address(&m.public(), &RK, 5, 1, &r).expect("valid M");
        assert_ne!(e5, e6, "epoch rotation stopped rotating");
        assert_ne!(e5, rev, "the two directions of one session collapsed into one box");
    }
}

// ---------------------------------------------------------------------------------------------
// PRIV-7a: the blob read key — turning "knowing the id" into "holding the key" (#294)
// ---------------------------------------------------------------------------------------------

/// Domain for deriving a blob's read keypair. Separated from every other KDF in the tree, so the
/// read secret can never coincide with the content key it is derived from, nor with a mailbox
/// fetch secret.
const BLOB_READ_DOMAIN: &[u8] = b"KARST-blob-read-v1";

/// Derive a blob's read keypair `(secret, public)` from the content key that already travels to the
/// recipient inside the `FileRef`.
///
/// **Why derive rather than add a field.** The recipient must end up holding the secret and the
/// relay must end up holding only the public half. The content key is already delivered E2E and
/// already means "you may read this blob" — deriving from it gives the relay a verifier without
/// changing the message format at all, and without inventing a second thing a sender could forget
/// to send.
///
/// **What it buys, stated exactly.** Today a blob download is bearer-by-id: the 256-bit `blob_id`
/// IS the right to fetch, so anyone who learns an id — a relay operator reading its own store, a
/// backup, a log — can pull the ciphertext. The bytes stay E2E-sealed either way, so this is not
/// about confidentiality of the content. It is about the RELAY being able to refuse a download to
/// someone who never held the key, which removes the id from the set of things that must stay
/// secret, and stops an id leak turning into unmetered traffic.
///
/// The secret is a Ristretto scalar and the public half is `secret·G`, so the existing
/// [`FetchOwnershipProof`] verifies it: the same Schnorr proof the blinded drop-boxes use, bound to
/// the cookie MAC so a captured proof cannot be replayed by a bystander.
pub fn blob_read_keypair(content_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut h = <Sha512 as sha2::Digest>::new();
    sha2::Digest::update(&mut h, BLOB_READ_DOMAIN);
    sha2::Digest::update(&mut h, content_key);
    let wide: [u8; 64] = sha2::Digest::finalize(h).into();
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    let p = (&s * RISTRETTO_BASEPOINT_TABLE).compress().to_bytes();
    (s.to_bytes(), p)
}

/// The context a blob read proof is bound to: the cookie MAC (freshness), the blob id and the
/// chunk index. Included in full so a proof captured for one chunk cannot be replayed for another.
pub fn blob_read_context(cookie_mac: &[u8; 16], blob_id: &[u8; 32], index: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + 32 + 4);
    v.extend_from_slice(cookie_mac);
    v.extend_from_slice(blob_id);
    v.extend_from_slice(&index.to_be_bytes());
    v
}

#[cfg(test)]
mod blob_read {
    use super::*;

    /// The same content key gives the same keypair on both sides — the recipient derives what the
    /// uploader registered, without any extra field on the wire.
    #[test]
    fn both_sides_derive_the_same_keypair_from_the_content_key() {
        let key = [7u8; 32];
        let (s1, p1) = blob_read_keypair(&key);
        let (s2, p2) = blob_read_keypair(&key);
        assert_eq!((s1, p1), (s2, p2), "the derivation is not deterministic");
        let (_, other) = blob_read_keypair(&[8u8; 32]);
        assert_ne!(p1, other, "different content keys must give different read keys");
    }

    /// The derived secret really opens the derived public half through the EXISTING proof, and a
    /// holder of a different key cannot.
    ///
    /// This is the property the whole slice rests on: the relay stores only the public half and
    /// runs the same verification the drop-boxes use.
    #[test]
    fn only_the_content_key_holder_can_prove_the_read_right() {
        let (sec, public) = blob_read_keypair(&[7u8; 32]);
        let ctx = blob_read_context(&[3u8; 16], &[9u8; 32], 4);
        let proof = FetchOwnershipProof::prove(&sec, &public, &ctx).expect("prove");
        assert!(proof.verify(&public, &ctx), "the real holder must be admitted");

        let (other_sec, _) = blob_read_keypair(&[8u8; 32]);
        let forged = FetchOwnershipProof::prove(&other_sec, &public, &ctx).expect("prove");
        assert!(
            !forged.verify(&public, &ctx),
            "a different content key must NOT open the blob — the id alone would be the right again"
        );
    }

    /// The proof is bound to the cookie AND to the chunk: a proof captured on the wire cannot be
    /// replayed for the next chunk, nor by a bystander holding a different cookie.
    #[test]
    fn a_captured_proof_does_not_travel_to_another_chunk_or_cookie() {
        let (sec, public) = blob_read_keypair(&[7u8; 32]);
        let ctx0 = blob_read_context(&[3u8; 16], &[9u8; 32], 0);
        let proof = FetchOwnershipProof::prove(&sec, &public, &ctx0).expect("prove");
        assert!(proof.verify(&public, &ctx0));

        let next_chunk = blob_read_context(&[3u8; 16], &[9u8; 32], 1);
        assert!(!proof.verify(&public, &next_chunk), "replayed onto another chunk");

        let other_cookie = blob_read_context(&[4u8; 16], &[9u8; 32], 0);
        assert!(!proof.verify(&public, &other_cookie), "replayed under another cookie");

        let other_blob = blob_read_context(&[3u8; 16], &[1u8; 32], 0);
        assert!(!proof.verify(&public, &other_blob), "replayed onto another blob");
    }
}
