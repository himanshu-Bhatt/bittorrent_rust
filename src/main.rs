// use serde::de;
use serde_json;
// use std::any::type_name;
use std::{env, usize};

// Available if you need it!
// use serde_bencode

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

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        // eprintln!("Logs from your program will appear here!");

        // Uncomment this block to pass the first stage
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value).0.to_string();
        println!("{}", decoded_value);
    } else {
        eprintln!("unknown command: {}", args[1])
    }
}
