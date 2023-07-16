#[derive(Debug, PartialEq)]
pub struct DataTooLarge();

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
}
