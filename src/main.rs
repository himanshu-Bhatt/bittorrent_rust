use serde_json;
// use std::any::type_name;
use std::{env, usize};

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    //if encoded value satrt with i its integers
    if let Some(rest) = encoded_value.strip_prefix('i') {
        if let Some((digits, _)) = rest.split_once('e') {
            // print!("holla");

            // return serde_json::Value::Number(digits.into())
            // println!("{}", type_name::<typeof(digits)>());
            if let Ok(n) = digits.parse::<i64>() {
                return n.into();
            }
            // return digits.into();
        }
        // let string = &encoded_value[1..encoded_value.len() - 1];
    }
    // If encoded_value starts with a digit, it's a number
    else if encoded_value.chars().next().unwrap().is_digit(10) {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number = number_string.parse::<i64>().unwrap();
        let string = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
        return serde_json::Value::String(string.to_string());
    }
    //  else {
    panic!("Unhandled encoded value: {}", encoded_value);
    // }
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
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value);
    } else {
        eprintln!("unknown command: {}", args[1])
    }
}
