use std::{error::Error, fmt};

use crate::block::{add_padding, xor, xor_inplace, BlockSize};

use self::ffi_openssl::{aes_decrypt, aes_encrypt, AesKeyDecrypt, AesKeyEncrypt};
mod ffi_openssl;
use rand::prelude::*;

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

impl Error for InvalidCiphertext {}

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
    if ciphertext.len() % 16 != 0 || ciphertext.is_empty() {
        return Err(InvalidCiphertext(ciphertext.len()).into());
    }

    let mut plaintext = vec![0; ciphertext.len()];

    for (plain_block, cipher_block) in plaintext
        .chunks_exact_mut(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks(BlockSize::AES_BLK_SZ_USIZE))
    {
        let cipher_block_16: &[u8; 16] = cipher_block.try_into()?;
        aes_decrypt(cipher_block_16, plain_block.try_into()?, &key);
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

    let mut ciphertext = vec![0; plaintext.len()];

    let key = AesKeyEncrypt::new(key)?;
    for (plain_block, cipher_block) in plaintext
        .chunks_exact(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks_exact_mut(16))
    {
        let cipher_block: &mut [u8; 16] = cipher_block.try_into()?;
        let xored_block = xor(plain_block, &last_cipher)?;
        aes_encrypt(&(*xored_block).try_into()?, cipher_block, &key);
        last_cipher = *cipher_block;
    }

    Ok(ciphertext)
}

pub fn encrypt_ecb(plaintext: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let plaintext = add_padding(&Vec::from(plaintext), BlockSize::AES_BLK_SZ)?;
    let mut ciphertext = vec![0; plaintext.len()];

    let key = AesKeyEncrypt::new(key)?;
    for (plain_block, cipher_block) in plaintext
        .chunks_exact(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks_exact_mut(16))
    {
        let cipher_block: &mut [u8; 16] = cipher_block.try_into()?;
        aes_encrypt(&(*plain_block).try_into()?, cipher_block, &key);
    }

    Ok(ciphertext)
}

pub fn decrypt_ecb(ciphertext: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let mut plaintext = vec![0; ciphertext.len()];

    let key = AesKeyDecrypt::new(key)?;
    for (plain_block, cipher_block) in plaintext
        .chunks_exact_mut(BlockSize::AES_BLK_SZ_USIZE)
        .zip(ciphertext.chunks_exact(16))
    {
        aes_decrypt(cipher_block.try_into()?, plain_block.try_into()?, &key);
    }

    // We know it's not going to be null because there has to be padding
    let padding_len = plaintext[plaintext.len() - 1];
    plaintext.resize(plaintext.len() - padding_len as usize, 0);
    Ok(plaintext)
}

#[derive(PartialEq, Debug)]
pub enum Protocol {
    Ecb,
    Cbc,
}

pub fn unknown_encryption(data: &[u8]) -> Result<(Protocol, Vec<u8>), Box<dyn Error + 'static>> {
    let mut rng = rand::thread_rng();

    let mut gen_padding = |size_range| -> Vec<u8> {
        let size: i32 = rng.gen_range(size_range);
        (0..size).map(|_| rng.gen()).collect()
    };

    let padded_data = [gen_padding(5..10), data.to_vec(), gen_padding(5..10)].concat();

    let key = rng.gen();

    if random::<bool>() {
        let iv = rng.gen();
        Ok((Protocol::Cbc, encrypt_cbc(&padded_data, &iv, &key)?))
    } else {
        Ok((Protocol::Ecb, encrypt_ecb(&padded_data, &key)?))
    }
}

/// Oracle that can detect wether a function encodes data using ECB or CBC
/// The function can add some padding at the beginning or at the end (less than 1 block)
/// We send the same character enough time to be able to skip the padding and detect
/// repeating block encryption (same input data -> same output means ECB)
pub fn oracle(func: impl FnOnce(&[u8]) -> Vec<u8>) -> Protocol {
    let test_data = b"a".repeat(16 * 3);
    let result = func(&test_data);

    let result = result.iter().skip(16);
    let first = result.clone().take(16).copied().collect::<Vec<u8>>();
    let second = result.skip(16).take(16).copied().collect::<Vec<u8>>();
    if first == second {
        Protocol::Ecb
    } else {
        Protocol::Cbc
    }
}

#[cfg(test)]
mod tests {
    use crate::aes::*;

    #[test]
    fn test_ecb() {
        for plaintext in [
            b"".to_vec(),
            b"0".to_vec(),
            b"YELLOW SUBMARINE".to_vec(),
            b"banana banana banana".to_vec(),
        ] {
            let key: &[u8; 16] = b"AZERTYUIOPASDFGH";
            let ciphertext = encrypt_ecb(&plaintext, key).unwrap();
            let decrypted_ciphertext = decrypt_ecb(&ciphertext, key).unwrap();

            assert_ne!(ciphertext, plaintext);
            assert_eq!(plaintext, decrypted_ciphertext);
        }
    }

    #[test]
    fn test_cbc() {
        let iv = b"ivIVivIVivIVivIV";
        for (plaintext, cipher_len) in [
            (b"".to_vec(), 16),
            (b"0".to_vec(), 16),
            (b"YELLOW SUBMARINE".to_vec(), 32),
            (b"banana banana banana".to_vec(), 32),
        ] {
            let key = b"AZERTYUIOPASDFGH";
            let ciphertext = encrypt_cbc(&plaintext, iv, key).unwrap();
            assert_eq!(ciphertext.len(), cipher_len);
            let decrypted_ciphertext = decrypt_cbc(&ciphertext, iv, key).unwrap();

            assert_ne!(ciphertext, plaintext);
            assert_eq!(plaintext, decrypted_ciphertext);

            assert!(decrypt_cbc(&ciphertext[..5], iv, key,).is_err());
        }
    }
}
