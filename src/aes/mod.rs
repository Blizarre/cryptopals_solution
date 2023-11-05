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

pub fn encrypt_with_random_key_prepost(data: &[u8]) -> Result<Vec<u8>, Box<dyn Error + 'static>> {
    let mut rng = rand::thread_rng();

    let pre_padding_sz = rng.gen_range(5..10);
    let pre_padding: Vec<u8> = (0..pre_padding_sz).map(|_| rng.gen()).collect();
    let post_padding_sz = rng.gen_range(5..10);
    let post_padding: Vec<u8> = (0..post_padding_sz).map(|_| rng.gen()).collect();

    let padded_data = [pre_padding, data.to_vec(), post_padding].concat();

    let key = rng.gen();

    if random() {
        let iv = rng.gen();
        encrypt_cbc(&padded_data, &iv, &key)
    } else {
        encrypt_ecb(&padded_data, &key)
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
