use std::{error::Error, fmt};

use openssl::error::ErrorStack;

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

impl Error for InvalidBlockSize {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

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

impl Error for DataTooLarge {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

#[derive(Debug, PartialEq)]
pub struct IncompatibleVectorLength(usize, usize);

impl fmt::Display for IncompatibleVectorLength {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Incompatible vector lengths: {} and {}", self.0, self.1)
    }
}

impl Error for IncompatibleVectorLength {
    fn cause(&self) -> Option<&dyn Error> {
        None
    }
}

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

pub fn decrypt_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher: openssl::symm::Cipher = openssl::symm::Cipher::aes_128_ecb();
    let plaintext = openssl::symm::decrypt(cipher, key, None, ciphertext)?;
    Ok(plaintext)
}

pub fn encrypt_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher: openssl::symm::Cipher = openssl::symm::Cipher::aes_128_ecb();
    let ciphertext = openssl::symm::encrypt(cipher, key, None, plaintext)?;
    Ok(ciphertext)
}

/// This is horrible. But it works, mostly... Need to check if I can access
/// a lower level primitive do decrypt a single aes block instread of hacking an
/// ECB stream with a fake padding
/// What I really wanted was access to the low-level method AES_encrypt which doesn't seem
/// to be exposed by the openssl crate: https://man.openbsd.org/AES_encrypt.3
pub fn decrypt_cbc(
    ciphertext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let mut last_cipher = iv;

    // We pad the cbc ciphertext with the PKCK#7 padding for an ecb cipher (16 chars of \0).
    // This ensure that the Openssl ecb cipher will accept the ciphertext and decrypt the whole of
    // the cbc ciphertext and its padding (which are xor-ed).
    let padded_ciphertext = {
        let mut v = Vec::from(ciphertext);
        v.append(&mut encrypt_ecb(b"", key)?);
        v
    };

    // Now we got the xored (plaintext + padding)
    let mut padded_plaintext = decrypt_ecb(&padded_ciphertext, key)?;

    // We go through each block and xor it in place with the previous ciphertext to get the
    // plaintext + padding
    for (plain_block, cipher_block) in padded_plaintext
        .chunks_mut(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks(BlockSize::AES_BLK_SZ_USIZE))
    {
        xor_inplace(plain_block, last_cipher)?;
        last_cipher = cipher_block;
    }

    // Now we return the result without the padding
    let padding_size = padded_plaintext[padded_plaintext.len() - 1] as usize;
    Ok(padded_plaintext[..padded_plaintext.len() - padding_size].into())
}

pub fn encrypt_cbc(
    plaintext: &[u8],
    iv: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let mut last_cipher = Vec::from(iv);
    let plaintext = add_padding(&Vec::from(plaintext), BlockSize::AES_BLK_SZ)?;
    let mut result = Vec::with_capacity(plaintext.len());

    for plain_block in plaintext.chunks(BlockSize::AES_BLK_SZ_USIZE) {
        let xored_block = xor(plain_block, &last_cipher)?;
        let mut cipher_block = encrypt_ecb(&xored_block, key)?;
        cipher_block.resize(16, 0);
        result.append(&mut cipher_block.clone());
        last_cipher = cipher_block;
    }

    // Now we return the result without the ecb padding
    Ok(result)
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
    fn test_ecb() {
        for plaintext in [
            b"".to_vec(),
            b"0".to_vec(),
            b"YELLOW SUBMARINE".to_vec(),
            b"banana banana banana".to_vec(),
        ] {
            let key = "AZERTYUIOPASDFGH".as_bytes();
            let ciphertext = encrypt_ecb(&plaintext, key).unwrap();
            let decrypted_ciphertext = decrypt_ecb(&ciphertext, key).unwrap();

            assert_ne!(ciphertext, plaintext);
            assert_eq!(plaintext, decrypted_ciphertext);
        }
    }

    #[test]
    fn test_cbc() {
        let iv: Vec<u8> = [0, 1, 2].iter().cycle().take(16).copied().collect();
        for (plaintext, cipher_len) in [
            (b"".to_vec(), 16),
            (b"0".to_vec(), 16),
            (b"YELLOW SUBMARINE".to_vec(), 32),
            (b"banana banana banana".to_vec(), 32),
        ] {
            let key = "AZERTYUIOPASDFGH".as_bytes();
            let ciphertext = encrypt_cbc(&plaintext, &iv, key).unwrap();
            assert_eq!(ciphertext.len(), cipher_len);
            let decrypted_ciphertext = decrypt_cbc(&ciphertext, &iv, key).unwrap();

            assert_ne!(ciphertext, plaintext);
            assert_eq!(plaintext, decrypted_ciphertext);
        }
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
