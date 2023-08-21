#[derive(Debug, PartialEq)]
pub struct ParseError(String);

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

#[cfg(test)]
mod tests {
    use crate::hex::*;

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
}
