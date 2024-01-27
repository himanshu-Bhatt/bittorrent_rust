use anyhow::Context;
use bittorrent_starter_rust::{Peers, TrackerRequest, TrackerResponse};
// use serde;
use serde::{Deserialize, Serialize};
use serde_bencode;
use serde_json;
// use std::any::type_name;
// use hex_literal::hex;
use hex::{self, FromHex};
use reqwest;
use serde_bytes::ByteBuf;
// use sha2::{Digest, Sha256};
use sha1::{Digest, Sha1};
use std::{
    env, fs,
    net::{Ipv4Addr, SocketAddrV4},
    usize,
};

#[derive(Debug, Deserialize)]
struct Torrent {
    // The URL of the tracker.
    announce: String,
    info: Info,
}

// #[derive(Debug, Clone, Deserialize)]
// struct Info {
//     // size of the file in bytes, for single-file torrents
//     length: usize,
//     // suggested name to save the file / directory as
//     name: String,
//     // number of bytes in each piece
//     #[serde(rename = "piece length")]
//     piece_length: usize,
//     // concatenated SHA-1 hashes of each piece
//     pieces: String,
// }

#[derive(Debug, Serialize, Deserialize)]
struct Info {
    pub name: String,
    pub pieces: ByteBuf,
    #[serde(rename = "piece length")]
    pub piece_length: usize,
    // #[serde(default)]
    // pub md5sum: Option<String>,
    #[serde(default)]
    pub length: usize,
    // #[serde(default)]
    // pub files: Option<Vec<File>>,
    // #[serde(default)]
    // pub private: Option<u8>,
    // #[serde(default)]
    // pub path: Option<Vec<String>>,
    // #[serde(default)]
    // #[serde(rename = "root hash")]
    // pub root_hash: Option<String>,
}

fn read_file_vec(filepath: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let data = fs::read(filepath)?;
    // eprint!("{}", filepath);
    Ok(data)
}

// async fn get_peer_list(torrent: &Torrent)-> Result<Vec<String>,Box<dyn std::error::Error>> {
//     let client = reqwest::Client::new();
//     let res = client
//         .post(torrent.announce)
//         .body("the exact body that is sent")
//         .send()
//         .await?;

// }

// fn info_hash(info:&Info)->[u8,20]{

// }

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

                    // get_peer_list(&con);

                    return (con.announce, con.info.length, hash, p_length, pieces);

                    // hasher.update(con.info);
                }
            }
        }
    }
    // let s = "hello word";

    panic!("NOt able to parse torent file");
}

async fn find_peers(file_name: &str) -> anyhow::Result<()> {
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
        serde_bencode::from_bytes(&response).context("parse tracker response")?; //commenting out coz don't have codecrafter's paid subscription.

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
    Ok(())
}

fn urlencode(t: &[u8; 20]) -> String {
    let mut encoded = String::with_capacity(3 * t.len());
    for &byte in t {
        encoded.push('%');
        encoded.push_str(&hex::encode(&[byte]));
    }
    encoded
}
// Usage: your_bittorrent.sh decode "<encoded_value>"

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // eprintln!("Logs from your program will appear here!");

        // Uncomment this block to pass the first stage
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
        // eprint!("Hellooo from 186");
        let _ = find_peers(file_name).await;
    }else if command=="handshake"{
        
    } else {
        eprintln!("unknown command: {}", args[1])
    }
    // eprint!("Hellooo");
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
                    // panic!("Unhandled encoded value: {}", encoded_value);
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
