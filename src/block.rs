use std::{error::Error, fmt};

use openssl::error::ErrorStack;

#[derive(Debug, PartialEq)]
pub struct DataTooLarge();

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
    for (plain_block, cipher_block) in padded_plaintext.chunks_mut(16).zip(ciphertext.chunks(16)) {
        xor_inplace(plain_block, last_cipher)?;
        last_cipher = cipher_block;
    }

    // Now we return the result without the padding
    let padding_size = padded_plaintext[padded_plaintext.len() - 1] as usize;
    Ok(padded_plaintext[..padded_plaintext.len() - padding_size].into())
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
}
