//! Fixed-size fetch (§2.2 metadata hardening): a fetch response occupies the SAME
//! number of bytes on the wire whether the mailbox holds 0, 1, or `FETCH_CAP`
//! messages, so an on-path observer cannot read the queue depth ("how much mail is
//! queued") from the response length. A `Counting` wrapper around the SERVER stream
//! records exactly how many bytes the relay puts on the wire toward the client.
//! Neuter the page padding (`FetchPage::pack` stops resizing to `FETCH_PAGE_LEN`)
//! and the counts diverge with queue depth.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use relay::node::Payload;
use node::seal::SkeletonSeal;
use node::session::{Session, NOISE_PARAMS};
use node::wire::{encode, FetchPage, WireResponse, FETCH_CAP, MAX_RESPONSE_FRAME};
use snow::Builder;

/// Stream wrapper counting bytes WRITTEN by the server (server -> client): the
/// Noise responder handshake message plus the framed, padded fetch response.
struct Counting {
    inner: TcpStream,
    written: Arc<AtomicUsize>,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Counting {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written.fetch_add(n, Ordering::SeqCst);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn a_seal() -> Payload {
    Payload::Skeleton(SkeletonSeal { kem_ct: Vec::new(), ephemeral_pub: [7u8; 32], nonce: [9u8; 12], ciphertext: vec![0xAB; 100] })
}

/// Serialize a `Fetched` response carrying `count` seals exactly as the relay does
/// (`encode` + Noise `write_msg`, cf. socket.rs) and return the bytes the server
/// puts on the wire toward the client.
fn response_wire_bytes(count: usize) -> usize {
    let kp = Builder::new(NOISE_PARAMS.parse().unwrap()).generate_keypair().unwrap();
    let relay_priv: [u8; 32] = kp.private.as_slice().try_into().unwrap();
    let relay_pub: [u8; 32] = kp.public.as_slice().try_into().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let written = Arc::new(AtomicUsize::new(0));
    let w2 = written.clone();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let counting = Counting { inner: stream, written: w2 };
        let mut sess = Session::accept(counting, &relay_priv).unwrap();
        // Drain the client's ping so the handshake is fully established first.
        let _ = sess.read_msg(1 << 20).unwrap();
        let seals: Vec<Payload> = (0..count).map(|_| a_seal()).collect();
        let resp = WireResponse::Fetched(FetchPage::pack(&seals));
        let bytes = encode(&resp).unwrap();
        sess.write_msg(&bytes, MAX_RESPONSE_FRAME).unwrap();
    });

    let mut sess = Session::connect(TcpStream::connect(addr).unwrap(), &relay_pub).unwrap();
    sess.write_msg(b"go", 1 << 20).unwrap();
    let _ = sess.read_msg(MAX_RESPONSE_FRAME).unwrap();
    server.join().unwrap();
    written.load(Ordering::SeqCst)
}

#[test]
fn fetch_response_size_is_constant_regardless_of_queue_depth() {
    let empty = response_wire_bytes(0);
    let one = response_wire_bytes(1);
    let full = response_wire_bytes(FETCH_CAP);
    assert_eq!(empty, one, "empty vs 1-message fetch: identical wire bytes (was {empty} vs {one})");
    assert_eq!(empty, full, "empty vs FETCH_CAP fetch: identical wire bytes (was {empty} vs {full})");
}
