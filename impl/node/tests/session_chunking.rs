//! A discriminating test for Noise session chunking. Every socket test sends small messages, so
//! the >64 KB path (`MAX_NOISE_PAYLOAD`) never fires — yet that is the path a full mailbox fetch
//! takes (~391 KB, several Noise frames). This is a direct Session round trip of a large payload,
//! byte for byte, isolated from the mailbox machinery.


use std::net::{TcpListener, TcpStream};
use std::thread;

use node::session::{Session, NOISE_PARAMS};
use snow::Builder;

#[test]
fn session_roundtrips_multichunk_payload() {
    let kp = Builder::new(NOISE_PARAMS.parse().unwrap()).generate_keypair().unwrap();
    let relay_priv: [u8; 32] = kp.private.as_slice().try_into().unwrap();
    let relay_pub: [u8; 32] = kp.public.as_slice().try_into().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // > MAX_NOISE_PAYLOAD (65519) → the payload is split across several Noise frames.
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let expect = big.clone();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut sess = Session::accept(stream, &relay_priv).unwrap();
        let got = sess.read_msg(1 << 20).unwrap();
        assert_eq!(got, expect, "the server must reassemble the multi-chunk byte for byte");
        sess.write_msg(&got, 1 << 20).unwrap(); // echo (also multi-chunk)
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut sess = Session::connect(stream, &relay_pub).unwrap();
    sess.write_msg(&big, 1 << 20).unwrap();
    let echoed = sess.read_msg(1 << 20).unwrap();
    assert_eq!(echoed, big, "the client must reassemble the echoed multi-chunk byte for byte");
    server.join().unwrap();
}
