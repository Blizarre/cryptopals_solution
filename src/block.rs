use std::{error::Error, fmt};

#[derive(Debug, Clone, Copy)]
pub struct BlockSize {
    value: u8,
}

impl BlockSize {
    pub fn new(size: usize) -> Result<BlockSize, InvalidBlockSize> {
        if size == 0 || size >= 256 {
            Err(InvalidBlockSize(0))
        } else {
            Ok(BlockSize { value: size as u8 })
        }
    }

    pub const AES_BLK_SZ_U8: u8 = 16;
    pub const AES_BLK_SZ_USIZE: usize = 16;

    pub const AES_BLK_SZ: BlockSize = BlockSize {
        value: BlockSize::AES_BLK_SZ_U8,
    };
}

#[derive(Debug, PartialEq)]
pub struct InvalidBlockSize(usize);

impl fmt::Display for InvalidBlockSize {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid block size {} (must be >0 and <256)", self.0)
    }
}

impl Error for InvalidBlockSize {}

#[derive(Debug, PartialEq)]
pub struct DataTooLarge {
    got_size: usize,
    max_size: usize,
}

impl fmt::Display for DataTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Data string too large: size {}, max {}",
            self.got_size, self.max_size
        )
    }
}

impl Error for DataTooLarge {}

#[derive(Debug, PartialEq)]
pub struct IncompatibleVectorLength(usize, usize);

impl fmt::Display for IncompatibleVectorLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Incompatible vector lengths: {} and {}", self.0, self.1)
    }
}

impl Error for IncompatibleVectorLength {}

pub fn xor(v1: &[u8], v2: &[u8]) -> Result<Vec<u8>, IncompatibleVectorLength> {
    let mut result = Vec::from(v1);

    xor_inplace(&mut result, v2)?;

    Ok(result)
}

pub fn xor_inplace(v1: &mut [u8], v2: &[u8]) -> Result<(), IncompatibleVectorLength> {
    if v1.len() != v2.len() {
        return Err(IncompatibleVectorLength(v1.len(), v2.len()));
    }

    for (b1, b2) in v1.iter_mut().zip(v2.iter()) {
        *b1 ^= *b2;
    }
    Ok(())
}

fn pad_block(data: &[u8], block_size: BlockSize) -> Result<Vec<u8>, DataTooLarge> {
    if data.len() > block_size.value as usize {
        Err(DataTooLarge {
            got_size: data.len(),
            max_size: block_size.value as usize,
        })
    } else {
        let padding_len = block_size.value - data.len() as u8;
        Ok(data
            .iter()
            .chain([padding_len].iter().cycle().take(padding_len as usize))
            .copied()
            .collect())
    }
}

pub fn add_padding(data: &[u8], block_size: BlockSize) -> Result<Vec<u8>, InvalidBlockSize> {
    let to_add = data.len() % block_size.value as usize;
    let mut padded_data = Vec::from(&data[..data.len() - to_add]);

    // using expect because the error would not make sense to the caller,
    // and is a critical internal bug.
    // Never too sure about this, but that's how openssl does it.
    let mut padding = if to_add == 0 {
        pad_block(&[], block_size).expect("Unexpected error in add_padding #1")
    } else {
        pad_block(&data[data.len() - to_add..], block_size)
            .expect("Unexpected error in add_padding #2")
    };
    padded_data.append(&mut padding);
    Ok(padded_data)
}

#[cfg(test)]
mod tests {
    use crate::block::*;

    #[test]
    fn test_padding() {
        assert_eq!(
            pad_block(&[1, 2, 3], BlockSize::new(5).unwrap()),
            Ok(vec![1, 2, 3, 2, 2])
        );
        assert_eq!(
            pad_block(&[1, 2, 3], BlockSize::new(1).unwrap()),
            Err(DataTooLarge {
                got_size: 3,
                max_size: 1
            })
        );
        assert_eq!(
            pad_block(&[], BlockSize::new(4).unwrap()),
            Ok(vec![4, 4, 4, 4])
        );
    }

    #[test]
    fn test_xor() {
        assert_eq!(xor(&[], &[]), Ok(vec![]));
        assert_eq!(xor(&[], &[1]), Err(IncompatibleVectorLength(0, 1)));
        assert_eq!(xor(&[1], &[]), Err(IncompatibleVectorLength(1, 0)));
        assert_eq!(
            xor(&[0b00, 0b11, 0b1010], &[0b11, 0b01, 0b1100]),
            Ok(vec![0b11, 0b10, 0b0110])
        );

        let mut v1 = [0, 1, 0, 0];
        xor_inplace(&mut v1, &[1, 1, 1, 1]).unwrap();
        assert_eq!(v1, [1, 0, 1, 1]);
        assert_eq!(
            xor_inplace(&mut v1, &[2]),
            Err(IncompatibleVectorLength(4, 1))
        );
    }
    #[test]
    fn test_block_size() {
        assert!(BlockSize::new(0).is_err());
        assert!(BlockSize::new(300).is_err());
        assert!(BlockSize::new(257).is_err());
        assert!(BlockSize::new(10).is_ok())
    }

    #[test]
    fn test_add_padding() {
        let blk_sz_1 = BlockSize::new(1).unwrap();
        let blk_sz_6 = BlockSize::new(6).unwrap();

        assert_eq!(add_padding(&[], blk_sz_1).unwrap(), vec![1]);
        assert_eq!(add_padding(&[1], blk_sz_1).unwrap(), vec![1, 1]);
        assert_eq!(
            add_padding(&[1, 2, 3], blk_sz_6).unwrap(),
            vec![1, 2, 3, 3, 3, 3]
        );

        assert_eq!(
            add_padding(&[1, 2, 3, 4], blk_sz_6).unwrap(),
            vec![1, 2, 3, 4, 2, 2]
        );
        assert_eq!(
            add_padding(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10], blk_sz_6).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 2, 2]
        );
    }
}
