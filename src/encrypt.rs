#[derive(Debug, PartialEq)]
pub struct EmptyKeyError();

pub fn encode_xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>, EmptyKeyError> {
    if key.is_empty() {
        Err(EmptyKeyError())
    } else {
        Ok(data
            .iter()
            .zip(key.iter().cycle())
            .map(|(b, k)| b ^ k)
            .take(data.len())
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::encrypt::*;

    #[test]
    fn test_encode_xor() {
        assert_eq!(
            encode_xor(b"Everyone", b"is"),
            Ok(vec![44, 5, 12, 1, 16, 28, 7, 22])
        );
        assert_eq!(encode_xor(b"to", b"entitled"), Ok(vec![17, 1]));
        assert_eq!(encode_xor(b"test", b""), Err(EmptyKeyError()));
        assert_eq!(encode_xor(b"", b"test"), Ok(vec![]));
    }
}
