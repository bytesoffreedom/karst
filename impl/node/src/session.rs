//! Независимый защищённый сеанс (§15) — Noise_NK поверх произвольного
//! `Read + Write` потока (сейчас TCP; позже тот же слой над QUIC/Tor — сеанс
//! ЖИВЁТ НАД транспортом, как в спеке).
//!
//! **Noise_NK:** responder(relay) static известен инициатору (клиент знает
//! `relay_pub` вне канала, как адрес) → relay аутентифицирован клиенту
//! (анти-MITM); клиент АНОНИМЕН на транспорте (авторизация — cookie/capability/
//! fetch-auth ВНУТРИ туннеля, §15 требует сохранять admission поверх тоннеля);
//! per-session эфемеры → forward secrecy и закрытие on-path replay.
//!
//! **Крипта — snow (де-факто Rust-Noise, Apache-2.0/MIT), НЕ самодельная.**
//! Pure-Rust resolver (curve25519-dalek/chacha20poly1305/blake2 — наш стек, без
//! `ring` → кросс-компиляция под Android).
//!
//! **Это конфиденциальность + анти-MITM, НЕ обфускация транспорта.** Noise-handshake
//! опознаваем анализом трафика (msg1 — высокоэнтропийный эфемер без TLS-структуры), блокировка
//! по IP:port работает поверх шифрования. Обфускацию транспорта даёт внешний PT
//! (look-like-HTTPS, ECH) — следующий срез §15.
//!
//! **What IS now applied here: length-hiding padding.** The payload is padded to
//! fixed size buckets before encryption (see `pad_to_bucket`), so an on-path observer
//! reads only a size class, not the exact message length. This is metadata hardening
//! — it does NOT make the handshake look like HTTPS and does NOT defeat IP/port
//! blocking; that remains the future carrier / look-like-TLS work.
//!
//! **Внешняя граница доверия сместилась сюда:** непроверенные байты теперь —
//! handshake- и Noise-кадры. Bounded-read (сверка длины ДО аллокации, чистая
//! ошибка вместо паники/зависания) сохранён на ОБОИХ.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use snow::{Builder, TransportState};

/// Noise-паттерн. NK: known responder static, anonymous initiator.
pub const NOISE_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

/// Жёсткий предел Noise-сообщения (спека Noise). Payload на чанк — минус тег.
const MAX_NOISE_MSG: usize = 65535;
const MAX_NOISE_PAYLOAD: usize = MAX_NOISE_MSG - 16;

/// Потолок handshake-кадра. NK-сообщения крошечные (~48 Б); строгий кап на
/// внешней границе. Больше — отказ ДО аллокации.
const MAX_HANDSHAKE_MSG: usize = 1024;

/// A10-2: wall-clock ceiling on completing the Noise handshake, counted from entry
/// into `accept` — the earliest point reachable from THIS file (the raw TCP accept
/// happens in socket.rs, which is out of scope here; entry to `accept` trails it by a
/// handful of instructions, close enough to "from ACCEPT" to matter). socket.rs sets
/// only a PER-READ timeout on the socket (`CONN_READ_TIMEOUT`, 30s) — that bounds a
/// single blocking read, not the total time to get through the handshake. A peer that
/// sends one byte every ~29s, forever, never trips that per-read timeout, yet also
/// never completes `read_handshake`/`write_handshake` — it holds the caller's
/// `ConnLimiter` slot (socket.rs, `MAX_CONNECTIONS`) indefinitely for the cost of a
/// trickle of bytes. This bounds the TOTAL handshake instead. An NK handshake moves
/// one write and one read of well under `MAX_HANDSHAKE_MSG` (1024 B) each — even at a
/// deliberately throttled ~100 B/s that's done in a couple of seconds, so 15s is
/// generous headroom, not a tight budget. Worst-case overshoot is this deadline
/// plus `CONN_READ_TIMEOUT`: a read already blocked in the kernel when the deadline
/// passes isn't interrupted, only the NEXT read/write attempt is rejected.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

/// Borrowed stream that fails read/write with a "deadline exceeded" error once
/// `deadline` has passed — checked BEFORE attempting the underlying I/O, so a peer
/// trickling bytes just under socket.rs's per-read timeout still can't stall past the
/// total deadline. Wraps `&mut S` (not owned) and lives only for the duration of the
/// handshake in `accept_with_deadline`: the plain `S` is what `Session` keeps
/// afterward, so ordinary post-handshake traffic (bounded separately, by socket.rs's
/// `CONN_TOTAL_DEADLINE` / `MAX_REQUESTS_PER_CONN`) is untouched by this.
struct DeadlineIo<'a, S> {
    inner: &'a mut S,
    deadline: Instant,
}

impl<S> DeadlineIo<'_, S> {
    fn check(&self) -> io::Result<()> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "noise handshake deadline exceeded"));
        }
        Ok(())
    }
}

impl<S: Read> Read for DeadlineIo<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.inner.read(buf)
    }
}

impl<S: Write> Write for DeadlineIo<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.inner.flush()
    }
}

fn noise_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("noise: {e}"))
}

// ---- Length-hiding padding (§2.2 "content padded to fixed size buckets") ----
//
// The Noise session sends the payload length in the clear (the `total` prefix) and
// the ciphertext length tracks the plaintext length — so an on-path observer reads
// the exact message size. We close that by padding the payload to one of a few fixed
// BUCKETS *before* encryption: many distinct plaintext lengths collapse into one size
// class on the wire. This is metadata hardening only — it does NOT make the handshake
// look like HTTPS or defeat IP/port blocking (that needs an external carrier / a
// look-like-TLS transport, a later slice).

/// Fixed size classes. A payload is padded up to the smallest bucket that fits it;
/// above the top bucket it rounds up to a multiple of it (large fetch responses).
const BUCKETS: [usize; 6] = [128, 512, 1536, 4096, 16384, 65536];

/// 4-byte inner length header prepended before padding.
const PAD_HEADER: usize = 4;

/// Smallest bucket >= `n`, or `n` rounded up to a multiple of the top bucket. Called
/// ONLY on trusted local sizes (never on an attacker-supplied wire length), so the
/// above-ladder ceil rule can't be driven by a hostile input.
pub(crate) fn bucket_for(n: usize) -> usize {
    for &b in &BUCKETS {
        if n <= b {
            return b;
        }
    }
    let top = BUCKETS[BUCKETS.len() - 1];
    n.div_ceil(top) * top
}

/// Wrap `plaintext` as `[u32 len LE][plaintext][zero padding]` sized to a bucket. The
/// zero padding rides INSIDE the Noise-encrypted payload, so the observer sees only
/// the bucket size. Never empty (min bucket 128), which also removes the empty-payload
/// special case in `write_msg`.
fn pad_to_bucket(plaintext: &[u8]) -> Vec<u8> {
    let target = bucket_for(PAD_HEADER + plaintext.len());
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out.extend_from_slice(plaintext);
    out.resize(target, 0);
    out
}

/// Recover the plaintext from a decrypted padded payload. Validates the inner length
/// BEFORE slicing: a forged/oversized `real_len` yields a clean error, never an
/// over-read/panic (bounded-read ethos). `max` is the trusted plaintext cap.
fn unpad(padded: &[u8], max: usize) -> io::Result<Vec<u8>> {
    if padded.len() < PAD_HEADER {
        return Err(noise_io("padded payload shorter than header"));
    }
    let real_len =
        u32::from_le_bytes(padded[..PAD_HEADER].try_into().expect("4 bytes")) as usize;
    if real_len > max {
        return Err(noise_io("inner length exceeds max"));
    }
    // Subtract instead of `PAD_HEADER + real_len > padded.len()` so a near-u32::MAX
    // real_len cannot wrap the addition on a 32-bit target (padded.len() >= PAD_HEADER
    // holds from the guard above).
    if real_len > padded.len() - PAD_HEADER {
        return Err(noise_io("inner length exceeds padded payload"));
    }
    Ok(padded[PAD_HEADER..PAD_HEADER + real_len].to_vec())
}

/// Записать handshake-кадр: `u16` длина + байты.
fn write_handshake<S: Write>(s: &mut S, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| noise_io("handshake too large"))?;
    s.write_all(&len.to_le_bytes())?;
    s.write_all(msg)?;
    s.flush()
}

/// Прочитать handshake-кадр c bounded-read (кап `MAX_HANDSHAKE_MSG` до аллокации).
fn read_handshake<S: Read>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf)?;
    let len = u16::from_le_bytes(len_buf) as usize;
    if len > MAX_HANDSHAKE_MSG {
        return Err(noise_io("handshake frame too large"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// Зашифрованный сеанс над потоком `S`.
pub struct Session<S> {
    stream: S,
    noise: TransportState,
}

impl<S: Read + Write> Session<S> {
    /// Клиент (initiator): relay static известен → `-> e, es` / `<- e, ee`.
    pub fn connect(mut stream: S, relay_pub: &[u8; 32]) -> io::Result<Self> {
        let mut noise = Builder::new(NOISE_PARAMS.parse().map_err(noise_io)?)
            .remote_public_key(relay_pub)
            .map_err(noise_io)?
            .build_initiator()
            .map_err(noise_io)?;
        let mut buf = [0u8; MAX_NOISE_MSG];
        let n = noise.write_message(&[], &mut buf).map_err(noise_io)?;
        write_handshake(&mut stream, &buf[..n])?;
        let msg = read_handshake(&mut stream)?;
        noise.read_message(&msg, &mut buf).map_err(noise_io)?;
        let noise = noise.into_transport_mode().map_err(noise_io)?;
        Ok(Session { stream, noise })
    }

    /// Relay (responder): свой static private key. Bounded by `HANDSHAKE_DEADLINE`
    /// (A10-2) — see `accept_with_deadline`, which does the real work.
    pub fn accept(stream: S, relay_priv: &[u8; 32]) -> io::Result<Self> {
        Self::accept_with_deadline(stream, relay_priv, Instant::now() + HANDSHAKE_DEADLINE)
    }

    /// Like `accept`, but with an explicit handshake deadline instead of the
    /// production `HANDSHAKE_DEADLINE`. Production always goes through `accept`;
    /// this exists so a test can inject an already-past deadline (or a short one)
    /// and prove the wiring without waiting out the real 15s budget.
    fn accept_with_deadline(mut stream: S, relay_priv: &[u8; 32], deadline: Instant) -> io::Result<Self> {
        let mut noise = Builder::new(NOISE_PARAMS.parse().map_err(noise_io)?)
            .local_private_key(relay_priv)
            .map_err(noise_io)?
            .build_responder()
            .map_err(noise_io)?;
        let mut buf = [0u8; MAX_NOISE_MSG];
        let msg = read_handshake(&mut DeadlineIo { inner: &mut stream, deadline })?;
        noise.read_message(&msg, &mut buf).map_err(noise_io)?;
        let n = noise.write_message(&[], &mut buf).map_err(noise_io)?;
        write_handshake(&mut DeadlineIo { inner: &mut stream, deadline }, &buf[..n])?;
        let noise = noise.into_transport_mode().map_err(noise_io)?;
        Ok(Session { stream, noise })
    }

    /// Зашифровать и отправить `plaintext`. Кадр: `u32` полная длина + чанки
    /// `[u32 ct_len][ct]` (payload дробится по `MAX_NOISE_PAYLOAD`, т.к. одно
    /// Noise-сообщение ≤ 64 КБ, а ответ mailbox бывает больше). `max` — потолок
    /// полной длины (симметрично чтению).
    pub fn write_msg(&mut self, plaintext: &[u8], max: usize) -> io::Result<()> {
        if plaintext.len() > max {
            return Err(noise_io("outgoing message exceeds max"));
        }
        // Pad to a fixed bucket BEFORE encryption so the wire length is a size class,
        // not the true length. `total` and the ciphertext now track the bucket.
        let padded = pad_to_bucket(plaintext);
        let total = u32::try_from(padded.len()).map_err(|_| noise_io("message too large"))?;
        self.stream.write_all(&total.to_le_bytes())?;
        let mut ct = [0u8; MAX_NOISE_MSG];
        for chunk in padded.chunks(MAX_NOISE_PAYLOAD) {
            let n = self.noise.write_message(chunk, &mut ct).map_err(noise_io)?;
            let ct_len = u32::try_from(n).map_err(|_| noise_io("chunk too large"))?;
            self.stream.write_all(&ct_len.to_le_bytes())?;
            self.stream.write_all(&ct[..n])?;
        }
        self.stream.flush()
    }

    /// Прочитать и расшифровать сообщение. Bounded на ТРЁХ уровнях: полная
    /// длина сверяется с `max` ДО аллокации, каждый ct-чанк — с `MAX_NOISE_MSG`,
    /// и (A10-3) the NUMBER of chunks is bounded too — see `max_chunks` below.
    pub fn read_msg(&mut self, max: usize) -> io::Result<Vec<u8>> {
        // Wire cap derived from the TRUSTED plaintext `max`, not from the wire length:
        // the padded frame can be up to the bucket that fits `max`. This keeps the
        // pre-alloc DoS guard (`total > wire_cap` before allocating) intact.
        let wire_cap = bucket_for(PAD_HEADER + max);
        // A10-3: bound the CHUNK COUNT, not just the declared total. `write_msg`
        // always splits the padded payload into exactly `ceil(len / MAX_NOISE_PAYLOAD)`
        // pieces (`chunks()` yields that many, all maximal but the last), and any
        // legitimate `len` is at most `wire_cap` — so `max_chunks` below is EXACT, no
        // fudge factor. Before this bound, only `total` was checked: a hostile sender
        // could carry the same `total` across as many chunks as bytes in it (each
        // chunk needs >=1 plaintext byte to make progress, see the `n == 0` check),
        // forcing one AEAD decrypt per byte instead of one per `MAX_NOISE_PAYLOAD`
        // (65519 B). Concretely, for the largest frame the relay ever reads
        // (`MAX_BLOB_FRAME` = 65_000 -> `wire_cap` = 65536): legitimate = 2 chunks,
        // hostile (unbounded) = up to 65536 — the "tens of thousands of AEAD ops"
        // this closes.
        let max_chunks = wire_cap.div_ceil(MAX_NOISE_PAYLOAD);
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let total = u32::from_le_bytes(len_buf) as usize;
        if total > wire_cap {
            return Err(noise_io("incoming message exceeds max"));
        }
        let mut padded = Vec::with_capacity(total);
        let mut pt = [0u8; MAX_NOISE_MSG];
        let mut chunks = 0usize;
        while padded.len() < total {
            chunks += 1;
            if chunks > max_chunks {
                return Err(noise_io("too many chunks for declared message length"));
            }
            let mut ct_len_buf = [0u8; 4];
            self.stream.read_exact(&mut ct_len_buf)?;
            let ct_len = u32::from_le_bytes(ct_len_buf) as usize;
            if ct_len > MAX_NOISE_MSG {
                return Err(noise_io("noise chunk too large"));
            }
            let mut ct = vec![0u8; ct_len];
            self.stream.read_exact(&mut ct)?;
            let n = self.noise.read_message(&ct, &mut pt).map_err(noise_io)?;
            if n == 0 || padded.len() + n > total {
                // нет прогресса или перебор заявленной длины → злонамеренный ввод.
                return Err(noise_io("malformed chunk stream"));
            }
            padded.extend_from_slice(&pt[..n]);
        }
        // Strip padding + validate the inner length before returning the plaintext.
        unpad(&padded, max)
    }

    /// Test-only: like `write_msg`, but splits the padded payload into fixed
    /// `chunk_len`-sized pieces instead of `MAX_NOISE_PAYLOAD`-sized ones. Lets a
    /// test pick EXACTLY how many Noise frames one logical message costs, to drive
    /// `read_msg`'s `max_chunks` bound right at (and past) its boundary — something
    /// the production `write_msg` can't do, since it always chunks at the real
    /// per-message ceiling.
    #[cfg(test)]
    fn write_msg_with_chunk_len(&mut self, plaintext: &[u8], max: usize, chunk_len: usize) -> io::Result<()> {
        if plaintext.len() > max {
            return Err(noise_io("outgoing message exceeds max"));
        }
        let padded = pad_to_bucket(plaintext);
        let total = u32::try_from(padded.len()).map_err(|_| noise_io("message too large"))?;
        self.stream.write_all(&total.to_le_bytes())?;
        let mut ct = [0u8; MAX_NOISE_MSG];
        for chunk in padded.chunks(chunk_len.max(1)) {
            let n = self.noise.write_message(chunk, &mut ct).map_err(noise_io)?;
            let ct_len = u32::try_from(n).map_err(|_| noise_io("chunk too large"))?;
            self.stream.write_all(&ct_len.to_le_bytes())?;
            self.stream.write_all(&ct[..n])?;
        }
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn relay_keys() -> ([u8; 32], [u8; 32]) {
        let kp = Builder::new(NOISE_PARAMS.parse().unwrap()).generate_keypair().unwrap();
        let priv_: [u8; 32] = kp.private.as_slice().try_into().unwrap();
        let pub_: [u8; 32] = kp.public.as_slice().try_into().unwrap();
        (priv_, pub_)
    }

    #[test]
    fn a_connection_that_never_finishes_the_handshake_is_dropped_on_a_deadline() {
        let (relay_priv, _relay_pub) = relay_keys();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // The slowloris shape: a peer that connects and then sends NOTHING at all.
        let _silent_peer = TcpStream::connect(addr).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        // Mirrors socket.rs's per-read timeout so a NEUTERED fix fails this test by a
        // bounded ordinary read timeout instead of hanging forever — it must NOT
        // produce the "deadline exceeded" message the fixed code produces.
        server_stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        // Deadline already in the past: `accept_with_deadline` must fail on its very
        // FIRST read, without ever touching the silent socket. If it instead
        // performed the real read, this call would block for up to the 2s timeout
        // above (or forever, absent any read timeout) rather than returning at once.
        let already_past = Instant::now() - Duration::from_secs(1);
        let err = Session::accept_with_deadline(server_stream, &relay_priv, already_past)
            .err()
            .expect("an already-past deadline must reject the handshake");
        assert!(
            err.to_string().contains("deadline exceeded"),
            "must fail because of the handshake deadline specifically, not some other \
             I/O error (e.g. an ordinary read timeout): {err}"
        );
    }

    #[test]
    fn a_well_behaved_handshake_still_completes_under_a_generous_deadline() {
        // Control for the deadline test above: the mechanism must not cost a real,
        // prompt handshake anything. Neuter it (e.g. always use `HANDSHAKE_DEADLINE`
        // instead of the injected one, or drop the check) and this still passes —
        // it's the OTHER test that catches a broken/backwards check.
        let (relay_priv, relay_pub) = relay_keys();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            Session::accept_with_deadline(stream, &relay_priv, Instant::now() + Duration::from_secs(30))
                .expect("a real, prompt handshake must not be rejected by a generous deadline")
        });
        let client_stream = TcpStream::connect(addr).unwrap();
        let _client_session = Session::connect(client_stream, &relay_pub).expect("client side of a real handshake");
        server.join().unwrap();
    }

    #[test]
    fn read_msg_rejects_a_message_split_into_more_chunks_than_its_declared_length_could_legitimately_need() {
        let (relay_priv, relay_pub) = relay_keys();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut sess = Session::accept(stream, &relay_priv).unwrap();
            // Control: for max=128, wire_cap=bucket_for(132)=512, and
            // max_chunks=ceil(512/MAX_NOISE_PAYLOAD)=1 — the legitimate shape,
            // carried in exactly 1 chunk, must round-trip.
            let got = sess.read_msg(128).unwrap();
            assert_eq!(got, vec![7u8; 50], "well-behaved single-chunk message round-trips");
            // Attack: the SAME total (128), split into 2 chunks instead of 1. Must be
            // rejected specifically for exceeding the chunk-count bound — not for a
            // decode error, an oversized total, or any other reason.
            let err = sess.read_msg(128).unwrap_err();
            assert!(
                err.to_string().contains("too many chunks"),
                "must be rejected for chunk count specifically: {err}"
            );
        });

        let client_stream = TcpStream::connect(addr).unwrap();
        let mut client = Session::connect(client_stream, &relay_pub).unwrap();
        // 1 chunk of 128 bytes: exactly the legitimate shape for this size class.
        client.write_msg_with_chunk_len(&[7u8; 50], 128, 128).unwrap();
        // 2 chunks of 64 bytes each, for a total that only ever legitimately needs 1.
        client.write_msg_with_chunk_len(&[7u8; 50], 128, 64).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn padding_collapses_distinct_lengths_into_one_bucket() {
        // Discriminating: two different plaintext lengths that fit the same bucket pad
        // to the SAME on-wire length — that is the whole point. Neuter `pad_to_bucket`
        // (return the plaintext unpadded) and these lengths diverge -> red.
        // 10 and 100 both fit bucket 128 (header+payload <= 128) -> same wire length.
        assert_eq!(pad_to_bucket(&[0u8; 10]).len(), pad_to_bucket(&[0u8; 100]).len());
        assert_eq!(pad_to_bucket(&[0u8; 10]).len(), 128);
        // 200 lands in the next class (204 -> 512); 2000 in another (2004 -> 4096).
        assert_ne!(pad_to_bucket(&[0u8; 100]).len(), pad_to_bucket(&[0u8; 200]).len());
        assert_eq!(pad_to_bucket(&[0u8; 200]).len(), 512);
        assert_eq!(pad_to_bucket(&[0u8; 2000]).len(), 4096);
    }

    #[test]
    fn pad_unpad_roundtrips_across_bucket_boundaries() {
        for len in [0usize, 1, 123, 124, 508, 512, 1531, 1532, 4090, 70000] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let padded = pad_to_bucket(&pt);
            assert!(padded.len() >= PAD_HEADER + len, "bucket fits header+payload");
            assert_eq!(unpad(&padded, 1 << 20).unwrap(), pt, "roundtrip byte-identical (len {len})");
        }
    }

    #[test]
    fn unpad_rejects_forged_inner_length_without_panicking() {
        // A forged/oversized inner length must be a clean error, never a slice
        // over-read/panic. Neuter the `PAD_HEADER + real_len > padded.len()` check and
        // this panics instead of erroring -> red (caught as a failure).
        let mut forged = vec![0xFFu8; PAD_HEADER]; // real_len = u32::MAX
        forged.extend_from_slice(&[0u8; 8]); // but only 8 bytes follow
        assert!(unpad(&forged, 1 << 20).is_err(), "oversized inner length rejected");
        // Too short even for the header.
        assert!(unpad(&[0u8; 2], 1 << 20).is_err());
        // Inner length within the payload but above the semantic max.
        let mut ok_frame = 100u32.to_le_bytes().to_vec();
        ok_frame.resize(512, 0);
        assert!(unpad(&ok_frame, 50).is_err(), "inner length above max rejected");
        assert_eq!(unpad(&ok_frame, 200).unwrap().len(), 100, "within max accepted");
    }

    #[test]
    fn bucket_for_ceils_above_the_ladder() {
        assert_eq!(bucket_for(1), 128);
        assert_eq!(bucket_for(128), 128);
        assert_eq!(bucket_for(129), 512);
        assert_eq!(bucket_for(65536), 65536);
        // Above the top bucket: round up to a multiple of it.
        assert_eq!(bucket_for(65537), 131072);
        assert_eq!(bucket_for(200_000), 262144);
    }
}
