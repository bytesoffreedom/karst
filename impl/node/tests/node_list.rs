//! §12 discovery plane — node-list (which relays exist). This slice serves an OPERATOR-CURATED
//! set (self + configured peers); peer-to-peer gossip merge (with dial-verification) is a
//! separate slice. Pins: dedup by relay-id, addr union, empty-addr rejection, addr/set bounds,
//! and the list travelling correctly over the real socket.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use relay::node::{RelayDescriptor, RelayNode, MAX_ADDRS_PER_RELAY, MAX_KNOWN_RELAYS};
use relay::server::{RelayServer};
use node::socket::{SocketTransport};

const NOW: u64 = 1_000_000;

fn desc(n: u8, addr: &str) -> RelayDescriptor {
    RelayDescriptor { noise_pub: [n; 32], fetch_pub: [n; 32], addrs: vec![addr.into()], quic_addrs: Vec::new() }
}

#[test]
fn add_relay_dedups_by_id_and_unions_addrs() {
    let mut r = RelayNode::new(NOW);
    r.add_relay(desc(1, "a:1"));
    r.add_relay(desc(1, "b:2")); // same relay-id, a new dial hint
    let list = r.node_list();
    assert_eq!(list.len(), 1, "same relay-id must not duplicate");
    assert_eq!(list[0].addrs, vec!["a:1".to_string(), "b:2".to_string()], "addrs are unioned");
    r.add_relay(desc(1, "a:1")); // an addr already present is a no-op
    assert_eq!(r.node_list()[0].addrs.len(), 2);
}

#[test]
fn empty_addr_descriptors_are_dropped_and_addrs_are_capped() {
    let mut r = RelayNode::new(NOW);
    r.add_relay(RelayDescriptor { noise_pub: [9; 32], fetch_pub: [9; 32], addrs: vec![], quic_addrs: Vec::new() });
    assert!(r.node_list().is_empty(), "a descriptor with no dial hint is useless → dropped");

    let many: Vec<String> = (0..MAX_ADDRS_PER_RELAY + 3).map(|i| format!("h:{i}")).collect();
    r.add_relay(RelayDescriptor { noise_pub: [8; 32], fetch_pub: [8; 32], addrs: many, quic_addrs: Vec::new() });
    assert_eq!(r.node_list()[0].addrs.len(), MAX_ADDRS_PER_RELAY, "addr hints are bounded");
}

#[test]
fn the_known_set_is_bounded() {
    let mut r = RelayNode::new(NOW);
    for i in 0..(MAX_KNOWN_RELAYS as u32 + 20) {
        let mut nb = [0u8; 32];
        nb[..4].copy_from_slice(&i.to_be_bytes());
        r.add_relay(RelayDescriptor { noise_pub: nb, fetch_pub: [0; 32], addrs: vec![format!("h:{i}")], quic_addrs: Vec::new() });
    }
    assert!(r.node_list().len() <= MAX_KNOWN_RELAYS, "the served list never exceeds the bound");
}

#[test]
fn self_survives_the_frame_trim_when_seeded_first() {
    // The binary seeds SELF first, then peers. Gossip verifies a relay by confirming it serves
    // its OWN self-entry, so self must always land in the frame-fitting prefix — even on a
    // well-connected relay with many peers. Seed self, then enough long-addr peers to FORCE a
    // trim, and assert self is still served. (Neuter the seed order → the binary self-trims →
    // this reddens.)
    let mut r = RelayNode::new(NOW);
    let self_d = desc(1, "self.example:9000");
    r.add_relay(self_d.clone());
    for i in 0..127u32 {
        let mut nb = [0u8; 32];
        nb[..4].copy_from_slice(&i.to_be_bytes());
        nb[31] = 2; // distinct from self ([1;32])
        let long_addr = format!("{}{i}.example:9000", "x".repeat(230)); // force the trim
        r.add_relay(RelayDescriptor { noise_pub: nb, fetch_pub: [0; 32], addrs: vec![long_addr], quic_addrs: Vec::new() });
    }
    let served = r.node_list();
    assert!(served.len() < 128, "the frame trim must actually engage for this to be meaningful");
    assert!(
        served.iter().any(|d| d.relay_id_hex() == self_d.relay_id_hex()),
        "self (seeded first) must survive the frame trim, or it becomes unverifiable via gossip"
    );
}

#[test]
fn get_node_list_travels_over_the_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let mut relay = RelayNode::new(NOW);
    relay.add_relay(desc(7, "peer.example:9000"));
    let server = RelayServer::new(relay, Arc::new(move || NOW));
    let noise_pub = server.noise_public();
    thread::spawn(move || {
        let _ = server.serve_listener(listener);
    });

    let got = SocketTransport::new(addr, noise_pub)
        .get_node_list()
        .expect("node-list over the wire");
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].addrs, vec!["peer.example:9000".to_string()]);
    assert_eq!(got[0].relay_id_hex(), "07".repeat(64));
}
