#[derive(Debug, PartialEq)]
pub struct DataTooLarge();

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

pub fn padding(data: &[u8], block_size: u8) -> Result<Vec<u8>, DataTooLarge> {
    if data.len() > block_size as usize {
        Err(DataTooLarge())
    } else {
        let padding_len = block_size - data.len() as u8;
        Ok(data
            .iter()
            .chain([padding_len].iter().cycle().take(padding_len as usize))
            .copied()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use crate::block::*;

    #[test]
    fn test_padding() {
        assert_eq!(padding(&[1, 2, 3], 5), Ok(vec![1, 2, 3, 2, 2]));
        assert_eq!(padding(&[1, 2, 3], 1), Err(DataTooLarge()));
        assert_eq!(padding(&[], 4), Ok(vec![4, 4, 4, 4]));
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
}
