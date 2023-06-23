#[derive(Debug, PartialEq)]
pub struct ParseError(String);

#[derive(Debug, PartialEq)]
pub struct IncompatibleVectorLength();

pub fn xor(v1: &[u8], v2: &[u8]) -> Result<Vec<u8>, IncompatibleVectorLength> {
    if v1.len() != v2.len() {
        return Err(IncompatibleVectorLength());
    }

    let mut result = Vec::with_capacity(v1.len());

    for (b1, b2) in v1.iter().zip(v2.iter()) {
        result.push(b1 ^ b2);
    }
    Ok(result)
}

pub fn from_hex(hex_string: &str) -> Result<Vec<u8>, ParseError> {
    hex_string
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| {
            let val0 = chunk.first().and_then(|d| d.to_digit(16));
            let val1 = chunk.get(1).and_then(|d| d.to_digit(16));

            if val0.is_none() || val1.is_none() {
                return Err(ParseError("Invalid hex string".to_string()));
            }
            Ok((val0.unwrap() << 4 | val1.unwrap()) as u8)
        })
        .collect::<Result<Vec<u8>, ParseError>>()
}

// https://datatracker.ietf.org/doc/html/rfc4648#section-4
fn base64_char(b: u8) -> char {
    match b {
        0..=25 => (b + b'A') as char,
        26..=51 => (b - 26 + b'a') as char,
        52..=61 => (b - 52 + b'0') as char,
        62 => '+',
        63 => '/',
        _ => panic!("Invalid base64 character"),
    }
}

pub fn to_base64(data: &[u8]) -> String {
    let mut result = String::new();
    let mut state = 0u8;
    let mut state_size = 0u8;

    for b in data {
        match state_size {
            0 => {
                result.push(base64_char(b >> 2));
                state = (b & 0b11) << 4;
                state_size = 2;
            }
            2 => {
                result.push(base64_char(state | (b >> 4)));
                state = (b & 0b1111) << 2;
                state_size = 4;
            }
            4 => {
                result.push(base64_char(state | (b >> 6)));
                result.push(base64_char(b & 0b111111));
                state = 0;
                state_size = 0;
            }
            _ => panic!("Invalid state detected"),
        }
    }
    if state_size == 2 {
        result.push(base64_char(state));
        result.push_str("==");
    } else if state_size == 4 {
        result.push(base64_char(state));
        result.push('=');
    }
    result
}

#[test]
fn test_xor() {
    assert_eq!(xor(&[], &[]), Ok(vec![]));
    assert_eq!(xor(&[], &[1]), Err(IncompatibleVectorLength()));
    assert_eq!(xor(&[1], &[]), Err(IncompatibleVectorLength()));
    assert_eq!(
        xor(&[0b00, 0b11, 0b1010], &[0b11, 0b01, 0b1100]),
        Ok(vec![0b11, 0b10, 0b0110])
    );
}

#[test]
fn test_from_hex() {
    assert_eq!(
        from_hex("48656c6c6f2c20776f726c6421").unwrap(),
        "Hello, world!".as_bytes()
    );

    assert!(from_hex("").unwrap().is_empty());
    assert!(from_hex("1").is_err());
    assert!(from_hex("0A").unwrap() == from_hex("0a").unwrap());

    assert!(from_hex("48656c6c6f2c20776f726c6421").is_ok());
    assert!(from_hex("48656c6c6f2c20776f726c642").is_err());
    assert!(from_hex("48656c6c6f2c20776f726c642g").is_err());
}

#[test]
fn test_tobase64() {
    // The examples were generated from the shell:
    // ~ $ echo -en "\xfa" | base64
    // +g==

    assert_eq!(to_base64(b"Hello, world!!"), "SGVsbG8sIHdvcmxkISE=");
    assert_eq!(to_base64(b"Hello, world!"), "SGVsbG8sIHdvcmxkIQ==");
    assert_eq!(to_base64(b"Hello, world"), "SGVsbG8sIHdvcmxk");
    assert_eq!(to_base64(b"foobar"), "Zm9vYmFy");

    assert_eq!(to_base64(b""), "");
    assert_eq!(to_base64(&[0]), "AA==");
    assert_eq!(to_base64(&[0, 1]), "AAE=");
    assert_eq!(to_base64(&[0, 1, 2]), "AAEC");
    assert_eq!(to_base64(&[0, 1, 2, 0xff]), "AAEC/w==");
    assert_eq!(to_base64(&[0x0f]), "Dw==");
    assert_eq!(to_base64(&[0xfe]), "/g==");
    assert_eq!(to_base64(&[0xfa]), "+g==");
}
