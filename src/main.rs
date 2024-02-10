use anyhow::{Context};
use bittorrent_starter_rust::{Handshake, Peers, TrackerRequest, TrackerResponse};
use serde::{Deserialize, Serialize};
use serde_bencode;
use serde_json;
use hex;
use reqwest;
use serde_bytes::ByteBuf;
use bincode;
use sha1::{Digest, Sha1};
use std::io::Read;
use std::net::TcpStream;
use std::{
    env, fs,
    io::Write,
    net::{Ipv4Addr, SocketAddrV4},
    usize,
};
use tokio_util::codec::Decoder;
use bytes::{BytesMut, Buf};

#[derive(Debug, Deserialize)]
struct Torrent {
    // The URL of the tracker.
    announce: String,
    info: Info,
}


#[derive(Debug, Serialize, Deserialize)]
struct Info {
    pub name: String,
    pub pieces: ByteBuf,
    #[serde(rename = "piece length")]
    pub piece_length: usize,
    #[serde(default)]
    pub length: usize,
}

fn read_file_vec(filepath: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = fs::read(filepath)?;
    Ok(data)
}


fn get_info_hash(info_encoded: &Vec<u8>) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(&info_encoded);
    hasher
        .finalize()
        .try_into()
        .expect("GenericArray<_, 20> == [_; 20]")
}

fn parse_torrent_file(filename: &str) -> (String, usize, [u8; 20], usize, Vec<String>) {
    if let Ok(dir_path) = env::current_dir() {
        if let Some(filepath) = dir_path.join(filename).to_str() {
            if let Ok(content) = read_file_vec(filepath) {
                let content_as_bytes_slice = content.as_slice();
                if let Ok(con) = serde_bencode::from_bytes::<Torrent>(content_as_bytes_slice) {
                    let info_bytes = serde_bencode::to_bytes(&con.info).unwrap();
                    let hash = get_info_hash(&info_bytes);

                    let p_length: usize = con.info.piece_length;
                    let pieces: Vec<String> = con
                        .info
                        .pieces
                        .chunks_exact(20)
                        .map(|chunk| {
                            chunk
                                .iter()
                                .map(|byte| format!("{:02x}", byte))
                                .collect::<String>()
                        })
                        .collect();

                    return (con.announce, con.info.length, hash, p_length, pieces);

                }
            }
        }
    }

    panic!("NOt able to parse torent file");
}

async fn find_peers(file_name: &str) -> anyhow::Result<Vec<SocketAddrV4>> {
    let (url, length, info_hash, piece_length, pieces) = parse_torrent_file(file_name);

    let url_params = TrackerRequest {
        peer_id: String::from("00112233445566778899"),
        port: 6881,
        uploaded: 0,
        downloaded: 0,
        left: length,
        compact: 1,
    };
    let url_params = serde_urlencoded::to_string(&url_params)?;
    let _trcker_url = format!(
        "{}?{}&info_hash={}",
        url,
        url_params,
        &urlencode(&info_hash)
    );
    eprintln!("{_trcker_url}");
    let response = reqwest::get(_trcker_url)
        .await
        .context("queying the tracker url")?;
    let response = response.bytes().await.context("fetching response")?;
    let response: TrackerResponse =
        serde_bencode::from_bytes(&response).context("parse tracker response")?; //hardcoding peeers coz don't have codecrafter's paid subscription.

    let mut p_vec = Vec::new();
    p_vec.push(SocketAddrV4::new(Ipv4Addr::new(178, 62, 82, 89), 51470));
    p_vec.push(SocketAddrV4::new(Ipv4Addr::new(165, 232, 33, 77), 51467));
    p_vec.push(SocketAddrV4::new(Ipv4Addr::new(178, 62, 85, 20), 51489));

    let peer = Peers(p_vec);
    let response = TrackerResponse {
        interval: 1,
        peers: peer,
    };
    for peer in &response.peers.0 {
        println!("{}:{}", peer.ip(), peer.port());
    }
    return Ok(response.peers.0);
    // Ok(())
}

fn urlencode(t: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * t.len());
    for &byte in t {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[byte]));
    }
    encoded
}

struct MessageDecoder {}

const MAX: usize =1<<16;

impl Decoder for MessageDecoder {
    type Item = String;
    type Error = std::io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut
    ) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            // Not enough data to read length marker.
            return Ok(None);
        }

        // Read length marker.
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_le_bytes(length_bytes) as usize;

        // Check that the length is not too large to avoid a denial of
        // service attack where the server runs out of memory.
        if length > MAX {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Frame of length {} is too large.", length)
            ));
        }

        if src.len() < 4 + length {
            // The full string has not yet arrived.
            //
            // We reserve more space in the buffer. This is not strictly
            // necessary, but is a good idea performance-wise.
            src.reserve(4 + length - src.len());

            // We inform the Framed that we need more bytes to form the next
            // frame.
            return Ok(None);
        }

        // Use advance to modify src such that it no longer contains
        // this frame.
        let tag=src[5].to_vec();
        let data = src[4..4 + length].to_vec();
        src.advance(4 + length);

        // Convert the data to a string, or fail if it is not valid utf-8.
        match String::from_utf8(data) {
            Ok(string) => Ok(Some(string)),
            Err(utf8_error) => {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    utf8_error.utf8_error(),
                ))
            },
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value).0.to_string();
        println!("{}", decoded_value);
    } else if command == "info" {
        let file_name = &args[2];
        let (url, length, hash, p_len, pieces) = parse_torrent_file(file_name);
        println!("{}", url);
        println!("{}", length);
        println!("{:?}", hash);
        println!("{}", p_len);
        println!("{:?}", pieces);
    } else if command == "peers" {
        let file_name = &args[2];
        let _ = find_peers(file_name).await;
    } else if command == "handshake" {
        let peer_info = &args[3];
        let file_name = &args[2];
        let (_, _, hash, _, _) = parse_torrent_file(file_name);

        let mut stream = TcpStream::connect(peer_info)?;
        let handshake = Handshake {
            length: 19,
            bittorent: *b"BitTorrent protocol",
            reserved: [0; 8],
            info_hash: hash,
            peer_id: *b"00112233445566778899",
        };
        let serialized_handshake = bincode::serialize(&handshake)?;

        stream.write_all(&serialized_handshake)?;
        let mut res: [u8; std::mem::size_of::<Handshake>()] = [0; std::mem::size_of::<Handshake>()];
        stream.read(&mut res)?;
        let res = bincode::deserialize::<Handshake>(&res)?;
        let peer_id = hex::encode(&res.peer_id);
        println!("Peer ID {:?}", peer_id);
    } else {
        eprintln!("unknown command: {}", args[1])
    }
    Ok(())
}

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> (serde_json::Value, &str) {
    // match &encoded_value[0] {
    match encoded_value.chars().next() {
        Some('d') => {
            let mut values = serde_json::Map::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (k, remainder) = decode_bencoded_value(rest);
                let k = match k {
                    serde_json::Value::String(k) => k,
                    k => {
                        panic!("dict keys must be strings, not {k:?}");
                    }
                };
                let (v, remainder) = decode_bencoded_value(remainder);
                values.insert(k, v);
                rest = remainder;
            }
            return (values.into(), &rest[1..]);
        }
        Some('l') => {
            let mut values = Vec::new();
            let mut rest = encoded_value.split_at(1).1;
            while !rest.is_empty() && !rest.starts_with('e') {
                let (v, remainder) = decode_bencoded_value(rest);
                values.push(v);
                // eprintln!("{:?}", values);
                rest = remainder;
            }
            return (values.into(), &rest[1..]);
        }
        Some('i') => {
            if let Some((n, rest)) = encoded_value
                .strip_prefix('i')
                .and_then(|rest| rest.split_once('e'))
                .and_then(|(digits, rest)| {
                    let n = digits.parse::<i64>().ok()?;
                    Some((n, rest))
                })
            {
                return (n.into(), rest);
            }
        }
        Some('0'..='9') => {
            if let Some((string, rest)) = encoded_value.split_once(':').and_then(|(len, string)| {
                if let Ok(len) = len.parse::<usize>() {
                    // eprintln!("{}",&string[..len]);
                    Some((&string[..len], &string[len..]))
                } else {
                    None
                }
            }) {
                return (serde_json::Value::String(string.to_string()), rest);
            }
        }
        _ => {}
    }
    panic!("Unhandled encoded value: {}", encoded_value);
}
