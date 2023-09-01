use std::{error::Error, fmt};

use openssl::error::ErrorStack;

use crate::ffi_openssl::{decrypt, encrypt, AesKeyDecrypt, AesKeyEncrypt};

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

#[derive(Debug, PartialEq)]
pub struct InvalidCiphertext(usize);

impl fmt::Display for InvalidCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Invalid ciphertext length: {}. Must be not empty and a multiple of block size",
            self.0
        )
    }
}

impl Error for InvalidCiphertext {
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

// A lot of try_into to guarantee a known block size at the interface boundaries with ffi_openssl.
// It doesn't feel "clean", I would love `chunks_exact(16)` to return `[u8;16]`, but alas that's
// not supported by the type system...

pub fn decrypt_cbc(
    ciphertext: &[u8],
    iv: &[u8; 16],
    key: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let mut last_cipher = iv;
    let key = AesKeyDecrypt::new(key)?;
    if ciphertext.len() % 16 != 0 || ciphertext.len() == 0 {
        return Err(InvalidCiphertext(ciphertext.len()).into());
    }

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    plaintext.resize(ciphertext.len(), 0);

    for (plain_block, cipher_block) in plaintext
        .chunks_exact_mut(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks(BlockSize::AES_BLK_SZ_USIZE))
    {
        let cipher_block_16: &[u8; 16] = cipher_block.try_into()?;
        decrypt(cipher_block_16, plain_block.try_into()?, &key);
        xor_inplace(plain_block, last_cipher)?;
        last_cipher = cipher_block_16;
    }

    // We know it's not going to be null because there has to be padding
    let padding_len = plaintext[plaintext.len() - 1];
    plaintext.resize(plaintext.len() - padding_len as usize, 0);
    Ok(plaintext)
}

pub fn encrypt_cbc(
    plaintext: &[u8],
    iv: &[u8; 16],
    key: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let mut last_cipher = *iv;

    let plaintext = add_padding(&Vec::from(plaintext), BlockSize::AES_BLK_SZ)?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    ciphertext.resize(plaintext.len(), 0);

    let key = AesKeyEncrypt::new(key)?;
    for (plain_block, cipher_block) in plaintext
        .chunks_exact(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks_exact_mut(16))
    {
        let cipher_block: &mut [u8; 16] = cipher_block.try_into()?;
        let xored_block = xor(plain_block, &last_cipher)?;
        encrypt(&(*xored_block).try_into()?, cipher_block, &key);
        last_cipher = *cipher_block;
    }

    Ok(ciphertext)
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
            let ciphertext = encrypt_cbc(
                &plaintext,
                iv.as_slice().try_into().unwrap(),
                key.try_into().unwrap(),
            )
            .unwrap();
            assert_eq!(ciphertext.len(), cipher_len);
            let decrypted_ciphertext = decrypt_cbc(
                &ciphertext,
                iv.as_slice().try_into().unwrap(),
                key.try_into().unwrap(),
            )
            .unwrap();

            assert_ne!(ciphertext, plaintext);
            assert_eq!(plaintext, decrypted_ciphertext);

            assert!(decrypt_cbc(
                &ciphertext[..5],
                iv.as_slice().try_into().unwrap(),
                key.try_into().unwrap(),
            )
            .is_err());
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
