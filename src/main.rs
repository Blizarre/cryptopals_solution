extern crate env_logger;

use crate::conversion::{from_hex, to_base64, xor};
use crate::decoding::decode_xor;

mod conversion;
mod decoding;

fn main() {
    env_logger::init();

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
        String::from_utf8(decode_xor(
            &from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap()
        ))
        .unwrap(),
        "Cooking MC's like a pound of bacon"
    );
}
