use std::net::SocketAddrV4;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TrackerRequest {
    // a unique identifier for your client
    //  You can use something like 00112233445566778899.
    pub peer_id: String,

    // the port your client is listening on
    // You can set this to 6881
    pub port: usize,

    // the total amount uploaded so far
    pub uploaded: usize,
    // the total amount downloaded so far
    pub downloaded: usize,
    // the number of bytes left to download
    pub left: usize,
    // whether the peer list should use the compact representation
    pub compact: u8,
}
#[derive(Debug, Clone, Deserialize)]
pub struct TrackerResponse {
    // An integer, indicating how often your client should make a request to the tracker.
    pub interval: usize,
    // contains list of peers that your client can connect to.
    // Each peer is represented using 6 bytes. The first 4 bytes are the peer's IP address and the last 2 bytes are the peer's port number.
    // pub peers: Peers,
    pub peers: Peers,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Peers(pub Vec<SocketAddrV4>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handshake {
    // length of the protocol string (BitTorrent protocol) which is 19 (1 byte)
    pub length: u8,
    // the string BitTorrent protocol (19 bytes)
    pub bittorent: [u8; 19],
    // eight reserved bytes, which are all set to zero (8 bytes)
    pub reserved: [u8; 8],
    // sha1 infohash (20 bytes) (NOT the hexadecimal representation, which is 40 bytes long)
    pub info_hash: [u8; 20],
    // peer id (20 bytes) (you can use 00112233445566778899 for this challenge)
    pub peer_id: [u8; 20],
}



#[repr(u8)]
pub enum MessageTag {
    Unchoke = 1,
    Interested = 2,
    NotInterested=3,
    Have=4,
    Bitfield = 5,
    Request = 6,
    Piece = 7,
    Cancel=8
}
pub struct Message {
    pub tag: MessageTag,
    pub data: Vec<u8>,
}
