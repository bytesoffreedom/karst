//! End-to-end proof that length-hiding padding actually bounds the ON-WIRE byte
//! count into size classes (§2.2). A `Counting` wrapper around the client stream
//! records exactly how many bytes leave for the network; two different plaintext
//! lengths that share a bucket must produce the SAME wire byte count. Neuter the
//! padding (`pad_to_bucket` returns plaintext unchanged) and the counts diverge.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use node::session::{Session, NOISE_PARAMS};
use snow::Builder;

/// Stream wrapper counting bytes WRITTEN (client -> network).
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

/// Send one plaintext of `len` bytes over a fresh Noise session; return the total
/// bytes written to the wire by the client (handshake + framed padded ciphertext).
fn wire_bytes_for(len: usize) -> usize {
    let kp = Builder::new(NOISE_PARAMS.parse().unwrap()).generate_keypair().unwrap();
    let relay_priv: [u8; 32] = kp.private.as_slice().try_into().unwrap();
    let relay_pub: [u8; 32] = kp.public.as_slice().try_into().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut sess = Session::accept(stream, &relay_priv).unwrap();
        let _ = sess.read_msg(1 << 20).unwrap();
    });

    let written = Arc::new(AtomicUsize::new(0));
    let stream = Counting { inner: TcpStream::connect(addr).unwrap(), written: written.clone() };
    let mut sess = Session::connect(stream, &relay_pub).unwrap();
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    sess.write_msg(&payload, 1 << 20).unwrap();
    server.join().unwrap();
    written.load(Ordering::SeqCst)
}

#[test]
fn wire_byte_count_is_bucketed_not_the_true_length() {
    // 200 and 400 both fall in bucket 512 (header+payload <= 512) -> identical wire
    // footprint despite a 200-byte difference in real content.
    let a = wire_bytes_for(200);
    let b = wire_bytes_for(400);
    assert_eq!(a, b, "same bucket -> same on-wire byte count (was {a} vs {b})");

    // A message in a larger class has a larger footprint (the counter tracks size).
    let big = wire_bytes_for(2000); // bucket 4096
    assert!(big > a, "a bigger size class writes more bytes ({big} vs {a})");
}

#[test]
fn multichunk_fetch_sized_payloads_are_also_bucketed() {
    // The observation an adversary most wants is the size of a FETCH RESPONSE (how
    // much mail is queued), which lives in the multichunk regime (> MAX_NOISE_PAYLOAD,
    // several Noise frames). 200_000 and 250_000 both pad to bucket 262144, so their
    // on-wire byte counts must match despite a 50 KB difference in real content.
    let a = wire_bytes_for(200_000);
    let b = wire_bytes_for(250_000);
    assert_eq!(a, b, "same multichunk bucket -> same wire byte count (was {a} vs {b})");
}
