//! The skeleton-seal DEMO path: `Client` and `Recipient`.
//!
//! Moved out of the relay's module when the crate split landed (#143). These were never relay
//! code — they wrap a `Transport` and drive the `SkeletonSeal` envelope from the CLIENT side.
//! They sat beside `RelayNode` only because that file was the relay AND everything the relay's
//! tests happened to reach for, which is precisely the coupling the split removes. Nothing here
//! can name a `RelayNode`.
//!
//! Not the §2.1 path: see `peer` for the real one (PQXDH + Double Ratchet). This is the demo/test
//! route that `seal` still serves, kept honest about what it is.

use admission::capability::Capability;
use admission::cookie::Cookie;
use x25519_dalek::PublicKey;

use node::protocol::{
    fetch_proof, payload_id, AckRequest, FetchRequest, FetchResponse, Payload,
    Response, Transport, WireMessage,
};
use karst_crypto::seal::{Identity, SkeletonSeal};

/// A thin client: it seals a message (the §2.1 skeleton), passes admission (§7) with a real cookie
/// round trip, and sends it over the transport.
pub struct Client<T: Transport> {
    transport: T,
    capability: Capability, // issued by the relay; the client keeps it for proofs
    client_addr: Vec<u8>,
    carrier_id: Vec<u8>,
    cookie: Option<Cookie>,
    nonce_ctr: u64,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T, capability: Capability, client_addr: &[u8]) -> Self {
        Client {
            transport,
            capability,
            client_addr: client_addr.to_vec(),
            carrier_id: b"mem".to_vec(),
            cookie: None,
            nonce_ctr: 0,
        }
    }

    /// Send `plaintext` to the recipient with public key `recipient_pub`.
    ///
    /// Cookie refresh: the server answers `NeedCookie` both on first contact (no cookie yet) and
    /// on a STALE or epoch-changed cookie (§7.1, `COOKIE_TTL_SECS`=30 — a long-lived client will
    /// inevitably hit it). So the challenge is handled on EVERY send and retried EXACTLY once with
    /// the new cookie; everything else (`Accepted`, a genuine `Rejected` on the capability) is
    /// returned immediately — "the cookie expired, retry" is kept strictly separate from "the
    /// credential is bad, give up".
    ///
    /// Reusing the same nonce and proof on the retry is safe: the challenge is issued at Stage 1
    /// (cookie), BEFORE Stage 3 (replay) and Stage 4 (quota), so the first attempt recorded
    /// NOTHING — neither in the replay filter nor in the quota accounting.
    pub fn send(
        &mut self,
        recipient_pub: &x25519_dalek::PublicKey,
        recipient_kem_ek: &[u8],
        plaintext: &[u8],
        now: u64,
    ) -> Response {
        // The seal is hybrid now (PRIV-3), so this path needs the recipient's ML-KEM key as well as
        // its X25519 one. A malformed key is a caller error here rather than a wire hazard — this
        // demo path gets the key straight from the `Recipient` — but it is still surfaced as a
        // refusal instead of a panic, because the real path takes the same key off the wire.
        let sealed = match SkeletonSeal::seal(recipient_pub, recipient_kem_ek, plaintext) {
            Ok(s) => s,
            Err(e) => return Response::Rejected(format!("cannot seal to recipient: {e}")),
        };
        let nonce = format!("req-{}", self.nonce_ctr).into_bytes();
        self.nonce_ctr += 1;
        let proof = self.capability.prove(&nonce, 0);

        let mut msg = WireMessage {
            client_addr: self.client_addr.clone(),
            carrier_id: self.carrier_id.clone(),
            cookie: self.cookie,
            request_nonce: nonce,
            capability_proof: proof,
            recipient: recipient_pub.to_bytes(),
            payload: Payload::Skeleton(sealed),
        };

        // Up to two attempts: one challenge → refresh → one retry.
        for _ in 0..2 {
            match self.transport.send(&msg, now) {
                Response::NeedCookie(c) => {
                    self.cookie = Some(c);
                    msg.cookie = Some(c);
                    continue;
                }
                other => return other,
            }
        }
        // Two challenges in a row means a fresh cookie was refused immediately (an anomaly, not
        // ordinary expiry). Do not loop and do not mask it: return an honest error.
        Response::Rejected("persistent cookie challenge".into())
    }
}

/// The recipient: its own identity, the transport, and the relay's public key (for the fetch-auth
/// DH). It collects ONLY its own mailbox (`mailbox` = its own public key).
pub struct Recipient<T: Transport> {
    transport: T,
    identity: Identity,
    /// Long-lived ML-KEM half of the hybrid seal (PRIV-3). Generated per `Recipient` like the
    /// identity itself: this is the skeleton path, so there is no bundle to publish it in.
    kem: karst_crypto::seal::SealKemKeys,
    relay_pub: PublicKey,
    client_addr: Vec<u8>,
    carrier_id: Vec<u8>,
    cookie: Option<Cookie>,
}

impl<T: Transport> Recipient<T> {
    pub fn new(transport: T, identity: Identity, relay_pub: PublicKey) -> Self {
        Self::with_kem(transport, identity, karst_crypto::seal::SealKemKeys::generate(), relay_pub)
    }

    /// As [`Recipient::new`], but with a KEM half the caller derived (PRIV-3).
    ///
    /// The library path needs this: a recipient reloaded from a recovery phrase must re-derive the
    /// same KEM key it had before, or every envelope sealed to it becomes unopenable after a
    /// restart — silently, because the AEAD failure is indistinguishable from "not for us".
    pub fn with_kem(
        transport: T,
        identity: Identity,
        kem: karst_crypto::seal::SealKemKeys,
        relay_pub: PublicKey,
    ) -> Self {
        let client_addr = identity.public.to_bytes().to_vec();
        Recipient {
            transport,
            identity,
            kem,
            relay_pub,
            client_addr,
            carrier_id: b"mem".to_vec(),
            cookie: None,
        }
    }

    /// This recipient's ML-KEM encapsulation key — what a sender needs for the hybrid seal.
    pub fn kem_ek(&self) -> &[u8] {
        self.kem.ek()
    }

    pub fn public(&self) -> PublicKey {
        self.identity.public
    }

    /// Collect incoming mail: the cookie handshake (as in send) plus a mailbox ownership proof,
    /// then decrypt. `Ok(vec)` is the batch (possibly empty; `None` elements did not decrypt);
    /// `Err` is a failure (unreachable, protocol, auth refusal), kept separate from "empty" so
    /// that `recv` never confuses the two.
    pub fn receive(&mut self, now: u64) -> Result<Vec<Option<Vec<u8>>>, String> {
        let mailbox = self.identity.public.to_bytes();
        let shared = self.identity.dh(&self.relay_pub);
        // Up to two attempts: one challenge → refresh → retry with the proof.
        for _ in 0..2 {
            let proof = match self.cookie {
                Some(c) => fetch_proof(&shared, &c.mac, &mailbox),
                None => [0u8; 16], // no cookie yet → the server will challenge
            };
            let req = FetchRequest {
                mailbox,
                client_addr: self.client_addr.clone(),
                carrier_id: self.carrier_id.clone(),
                cookie: self.cookie,
                proof,
                own_proof: Vec::new(), // identity mailbox → DH proof above
            };
            match self.transport.fetch(&req, now) {
                FetchResponse::NeedCookie(c) => {
                    self.cookie = Some(c);
                    continue;
                }
                FetchResponse::Fetched(payloads) => {
                    // A skeleton recipient opens only `Skeleton` envelopes; session §2.1 ones are
                    // not addressed to it (they are handled by `Peer`) — so `None`, not a panic.

                    let opened: Vec<Option<Vec<u8>>> = payloads
                        .iter()
                        .map(|p| match p {
                            Payload::Skeleton(s) => self.kem.open(s, &self.identity),
                            Payload::Session(_) => None,
                        })
                        .collect();
                    // Every fetch is a LEASE now (#179) — the relay no longer offers
                    // delete-on-read — so a receiver that wants its mail gone has to say so.
                    // This one ACKs immediately, on receipt, which is the honest behaviour for a
                    // REFERENCE receiver: it holds nothing durable, so there is no later moment
                    // at which it would be safer to ACK. `Peer` (the real path) is the one that
                    // waits until the advanced ratchet is on disk. A failed ACK is not an error
                    // here: the messages simply stay leased and are redelivered.
                    //
                    // ONLY what it actually opened. An ACK says "the relay may forget this", and
                    // this receiver must not say that about mail it could not read: a
                    // `Payload::Session` envelope belongs to `Peer`, not here, and a seal that
                    // failed to open is not ours either. Those stay leased and redeliver to
                    // whoever they were for. (Before #179 the relay destroyed them regardless,
                    // which is precisely the behaviour that went away.)
                    let mine: Vec<[u8; 32]> = payloads
                        .iter()
                        .zip(opened.iter())
                        .filter(|(_, o)| o.is_some())
                        .map(|(p, _)| payload_id(p))
                        .collect();
                    if let (Some(cookie), false) = (self.cookie, mine.is_empty()) {
                        let ack = AckRequest {
                            mailbox,
                            client_addr: self.client_addr.clone(),
                            carrier_id: self.carrier_id.clone(),
                            cookie: Some(cookie),
                            proof: fetch_proof(&shared, &cookie.mac, &mailbox),
                            ids: mine,
                            own_proof: Vec::new(),
                        };
                        let _ = self.transport.ack(&ack, now);
                    }
                    return Ok(opened);
                }
                FetchResponse::Rejected(r) => return Err(r),
            }
        }
        Err("persistent cookie challenge".into())
    }
}
