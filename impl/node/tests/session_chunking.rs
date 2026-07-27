//! Дискриминирующий тест чанкования Noise-сессии. Все сокет-тесты гоняют мелкие
//! сообщения — путь >64КБ (`MAX_NOISE_PAYLOAD`) не срабатывает, а именно он
//! несёт fetch полного mailbox (~391КБ, несколько Noise-кадров). Здесь —
//! прямой Session round-trip большого payload'а, байт-в-байт, изолированно от
//! mailbox-машинерии.

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

    // > MAX_NOISE_PAYLOAD (65519) → payload дробится на несколько Noise-кадров.
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let expect = big.clone();

    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut sess = Session::accept(stream, &relay_priv).unwrap();
        let got = sess.read_msg(1 << 20).unwrap();
        assert_eq!(got, expect, "сервер должен собрать мультичанк байт-в-байт");
        sess.write_msg(&got, 1 << 20).unwrap(); // эхо (тоже мультичанк)
    });

    let stream = TcpStream::connect(addr).unwrap();
    let mut sess = Session::connect(stream, &relay_pub).unwrap();
    sess.write_msg(&big, 1 << 20).unwrap();
    let echoed = sess.read_msg(1 << 20).unwrap();
    assert_eq!(echoed, big, "клиент должен собрать эхо-мультичанк байт-в-байт");
    server.join().unwrap();
}
