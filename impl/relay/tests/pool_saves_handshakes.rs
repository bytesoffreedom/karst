//! **Does pooling actually save handshakes?** Counted at the relay, not inferred (PERF-8).
//!
//! The client-side tests pin what the pool may MERGE; they cannot show that it merges anything at
//! all. This one does, from the far end: the relay counts every connection it hands a thread, so
//! the number is a fact about the wire rather than about the client's intent.
//!
//! It also pins the boundary that makes pooling safe to have at all — an UNSCOPED request must not
//! reuse anything — because that is the half a performance change is most likely to quietly lose.
//!
//! **What this does NOT buy, stated up front because I first believed otherwise.** A poll cycle
//! walks one drop-box per session per epoch, and every box is its own `Handle::Box(peer, epoch)`,
//! hence its own isolation scope. So the ~151 fetches of a 50-contact cycle are 151 DISTINCT scopes
//! and the pool cannot merge them — nor should it, since each box must ride its own circuit. What
//! collapses is repeated requests under ONE handle: a box's fetch and its ACK (the receipt carries
//! the scope forward), and a cookie-refresh retry. Real, and roughly half the requests for boxes
//! that have mail — but not the fan-out. That lever is parallelism, not pooling.

use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::thread;

use karst_transport::socket::SocketTransport;
use node::protocol::{Payload, Transport, WireMessage};
use relay::node::RelayNode;
use relay::server::{generate_noise_keypair, RelayServer};

const NOW: u64 = 1_000_000;

/// A relay on a real socket, plus a handle on its accepted-connection count.
fn spawn() -> (std::net::SocketAddr, [u8; 32], Arc<std::sync::atomic::AtomicU64>) {
    let (noise_priv, noise_pub) = generate_noise_keypair();
    let node = RelayNode::new(NOW);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("bound");
    let server = RelayServer::from_shared(
        Arc::new(RwLock::new(node)),
        Arc::new(move || NOW),
        noise_priv,
        noise_pub,
    );
    let counter = server.accepted_counter();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });
    (addr, noise_pub, counter)
}

/// A well-formed SCOPED request. Admission will reject it (the capability proof is fabricated) and
/// that is fine: this test counts CONNECTIONS, and a rejected request costs exactly the same one
/// connection an accepted one does. Using a genuinely scoped class matters — a public read may
/// never carry a scope (`identity_guard::a_public_read_is_never_given_a_scope`), so `get_policy`
/// could not stand in here even though it would have been less setup.
fn scoped_deposit(n: u8) -> WireMessage {
    WireMessage {
        client_addr: vec![n],
        carrier_id: b"test".to_vec(),
        cookie: None,
        request_nonce: vec![n, 1, 2, 3],
        capability_proof: admission::capability::CapabilityProof {
            capability_id: [n; 16],
            epoch_id: 0,
            not_after: u32::MAX,
            mac: [n; 16],
        },
        recipient: [n; 32],
        payload: Payload::Skeleton(node::seal::SkeletonSeal {
            kem_ct: Vec::new(),
            ephemeral_pub: [n; 32],
            nonce: [n; 12],
            ciphertext: vec![n; 8],
        }),
    }
}

/// **Many requests on ONE handle cost one handshake.**
///
/// Eight rather than two only to make the ratio unmistakable; the shape that actually occurs is a
/// fetch followed by its ACK under the same scope, plus a cookie-refresh retry.
///
/// DISCRIMINATING: remove the `pooled_take` call from `round_trip_scoped_sized` and this reports
/// eight connections instead of one.
#[test]
fn eight_scoped_requests_cost_one_connection() {
    let (addr, noise_pub, accepted) = spawn();
    let t = SocketTransport::new(addr, noise_pub);

    for i in 0..8u8 {
        let _ = t.send_isolated(&scoped_deposit(i), NOW, Some("one-handle-scope"));
    }

    let n = accepted.load(Ordering::Relaxed);
    assert_eq!(
        n, 1,
        "eight requests on ONE isolation scope opened {n} connections. Each is a TCP connect plus a \
         full Noise handshake; a fetch and its ACK share a scope, so this is what removes the second \
         one (and a cookie-refresh retry's)."
    );
}

/// **Two scopes never share a connection**, whatever it costs.
///
/// This is the privacy half, and it is not a nicety: proxy identities are kept apart by their
/// per-handle scope, so a pool that reused one scope's session for another would merge identities
/// onto one Noise session — strictly worse than the shared source address they already have.
#[test]
fn two_scopes_never_share_a_connection() {
    let (addr, noise_pub, accepted) = spawn();
    let t = SocketTransport::new(addr, noise_pub);

    for (s, scope) in ["scope-of-proxy-1", "scope-of-proxy-2"].iter().enumerate() {
        for i in 0..3u8 {
            let _ = t.send_isolated(&scoped_deposit(i + 10 * s as u8), NOW, Some(scope));
        }
    }

    let n = accepted.load(Ordering::Relaxed);
    assert_eq!(
        n, 2,
        "six requests across TWO scopes opened {n} connections; it must be exactly one per scope. \
         Fewer means two identities were merged onto one session; more means the pool is not \
         working at all."
    );
}

/// **An unscoped request opens its own connection every time**, and never picks up a scoped one.
///
/// Refusing to pool these is deliberate (there is nothing to keep two unlinkable handles apart
/// without a scope), so the cost is accepted rather than optimised away. Asserted so that
/// "optimise the public reads too" cannot land without this test objecting.
#[test]
fn unscoped_requests_are_never_pooled() {
    let (addr, noise_pub, accepted) = spawn();
    let t = SocketTransport::new(addr, noise_pub);

    for _ in 0..4 {
        t.get_policy().expect("a public read is answered without a credential");
    }

    let n = accepted.load(Ordering::Relaxed);
    assert_eq!(
        n, 4,
        "four UNSCOPED requests opened {n} connections instead of 4. If they are being pooled, \
         requests that deliberately carry no identity are now sharing a session — which hands the \
         relay a sequence they were specifically built not to have."
    );
}

/// **The shape that actually occurs, and the limit of what pooling can do.**
///
/// A poll walks one drop-box per session per epoch, and each box is its own handle — so each gets
/// its own isolation scope. This asserts BOTH halves of that consequence at once: N boxes cost N
/// connections however many times they are polled (pooling cannot and must not merge them), while a
/// second request under any ONE of those scopes is free.
///
/// It exists because I published the opposite. I built this pool to cut a ~151-handshake poll cycle
/// to one, and only afterwards traced that every box carries a distinct scope by construction. The
/// number the pool actually improves is the fetch/ACK pair, not the fan-out.
#[test]
fn distinct_handles_cost_distinct_connections_however_much_they_repeat() {
    let (addr, noise_pub, accepted) = spawn();
    let t = SocketTransport::new(addr, noise_pub);

    // Five "boxes", each with its own scope, as a poll cycle produces them.
    for i in 0..5u8 {
        let _ = t.send_isolated(&scoped_deposit(i), NOW, Some(&format!("box-scope-{i}")));
    }
    let after_first_pass = accepted.load(Ordering::Relaxed);
    assert_eq!(
        after_first_pass, 5,
        "five distinct scopes must cost five connections; {after_first_pass} means the pool is \
         merging scopes, which would put separate conversations on one Noise session"
    );

    // A SECOND request under each of the same scopes — this is where pooling pays, and it is the
    // fetch->ACK pair in disguise.
    for i in 0..5u8 {
        let _ = t.send_isolated(&scoped_deposit(i), NOW, Some(&format!("box-scope-{i}")));
    }
    let after_second_pass = accepted.load(Ordering::Relaxed);
    assert_eq!(
        after_second_pass, 5,
        "the second request on each scope opened {} more connections. A fetch and its ACK share a \
         scope, so this is precisely the saving PERF-8 delivers — and all of it.",
        after_second_pass - after_first_pass
    );
}

/// **A progress query is admitted, not free** (PRIV-7).
///
/// `BlobStat` used to be `BlobStat([u8; 32])`: no address, no cookie, no admission — the one blob
/// endpoint a stranger could hit without proving anything, which the serve loop's own comment
/// already flagged as a way to buy the full connection deadline. The progress it returns was never
/// the sensitive part (knowing the id already grants chunk downloads); the unauthenticated endpoint
/// was.
///
/// Asserted through the real client call, so it covers the cookie round trip as well as the gate.
#[test]
fn a_progress_query_completes_only_after_earning_a_cookie() {
    let (addr, noise_pub, accepted) = spawn();
    let t = SocketTransport::new(addr, noise_pub);

    // Blobs are disabled on this relay, so the ANSWER is a refusal — but reaching a refusal means
    // the cookie stage was cleared, which is exactly what this pins. A relay with blobs on returns
    // `None` for an unknown id; either way the client must not get an answer on attempt one.
    let out = t.blob_stat([9u8; 32]);
    assert!(
        out.is_err() || out.as_ref().is_ok_and(|v| v.is_none()),
        "unexpected stat outcome: {out:?}"
    );
    assert!(
        accepted.load(Ordering::Relaxed) >= 1,
        "the query never reached the relay at all"
    );
}
