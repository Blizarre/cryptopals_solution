extern crate env_logger;

mod block;
mod conversion;
mod decrypt;
mod encrypt;

use std::fs::File;
use std::io::Read;

use crate::block::padding;
use crate::conversion::{from_base64, from_hex, to_base64, xor};
use crate::decrypt::{
    break_xor_single_char, find_key_block_xor, find_likely_xor_keysizes, hamming_distance,
    EnglishWordFreq,
};
use crate::encrypt::encode_xor;

fn main() {
    env_logger::init();

    set1();

    set2();
}

fn set1() {
    // Set1 Challenge1
    assert_eq!(
            to_base64(&from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap()),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );

    // Set1 Challenge2
    assert_eq!(
        xor(
            &from_hex("1c0111001f010100061a024b53535009181c").unwrap(),
            &from_hex("686974207468652062756c6c277320657965").unwrap()
        )
        .unwrap(),
        from_hex("746865206b696420646f6e277420706c6179").unwrap()
    );

    // Set1 Challenge3
    assert_eq!(
        String::from_utf8(
            break_xor_single_char::<EnglishWordFreq>(
                &from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                    .unwrap()
            )
            .unwrap()
            .decoded_content
        )
        .unwrap(),
        "Cooking MC's like a pound of bacon"
    );

    // Set1 Challenge4
    let mut data = String::new();
    File::open("data/4.txt")
        .and_then(|mut f| f.read_to_string(&mut data))
        .unwrap();

    let mut max_score = f32::MIN;
    let mut best_line = String::new();

    for line in data.split('\n') {
        let decoded = break_xor_single_char::<EnglishWordFreq>(&from_hex(line).unwrap());
        if let Some(decoded) = decoded {
            if decoded.score > max_score {
                max_score = decoded.score;
                best_line = String::from_utf8(decoded.decoded_content).unwrap();
            }
        }
    }
    assert_eq!(best_line, "Now that the party is jumping\n");

    // Set1 Challenge5
    assert_eq!(
        encode_xor(
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
            b"ICE"
        ),
        Ok(vec![
            11, 54, 55, 39, 42, 43, 46, 99, 98, 44, 46, 105, 105, 42, 35, 105, 58, 42, 60, 99, 36,
            32, 45, 98, 61, 99, 52, 60, 42, 38, 34, 99, 36, 39, 39, 101, 39, 42, 40, 43, 47, 32,
            67, 10, 101, 46, 44, 101, 42, 49, 36, 51, 58, 101, 62, 43, 32, 39, 99, 12, 105, 43, 32,
            40, 49, 101, 40, 99, 38, 48, 46, 39, 40, 47
        ])
    );

    // Set1 Challenge6
    assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37);

    let mut base64_data = String::new();
    File::open("data/6.txt")
        .and_then(|mut fd| fd.read_to_string(&mut base64_data))
        .unwrap();
    let data = &from_base64(&data).unwrap();
    let key_sizes = find_likely_xor_keysizes(data);
    let mut decoded = None;
    for key_size in key_sizes {
        if let Some(key) = find_key_block_xor(data, key_size) {
            let decoded_data = data
                .chunks(key_size)
                .map(|d| encode_xor(d, &key))
                .flatten()
                .flatten()
                .collect::<Vec<u8>>();
            decoded = Some(String::from_utf8(decoded_data).unwrap());
            break;
        }
    }
    assert_eq!(decoded, Some("Bob".to_string()));
}

fn set2() {
    assert_eq!(
        padding(b"YELLOW SUBMARINE", 20),
        Ok(Vec::from(b"YELLOW SUBMARINE\x04\x04\x04\x04".as_ref()))
    )
}
