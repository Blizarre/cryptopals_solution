/**
It is a bit weird to import the openssl bindings directly instead of using available crates like openssl
or openssl-sys, but none of them expose the low-level AES_encrypt and AES_decrypt functions.
*/
use std::{error::Error, fmt::Display};

use libc::{c_int, c_void};

#[repr(C)]
struct AesKeyFfi([c_int; 4 * (14 + 1)], c_int);

impl AesKeyFfi {
    fn new() -> AesKeyFfi {
        AesKeyFfi([0; 60], 0)
    }
}

#[derive(Debug)]
pub struct InternalKeyError {
    code: c_int,
}

impl Display for InternalKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AES Key expansion Error, code {}", self.code)
    }
}
impl Error for InternalKeyError {}
pub struct AesKeyDecrypt(AesKeyFfi);

impl AesKeyDecrypt {
    pub fn new(key_data: &[u8]) -> Result<AesKeyDecrypt, InternalKeyError> {
        let mut key = AesKeyFfi::new();
        let ret = unsafe { AES_set_decrypt_key(key_data.as_ptr(), 128, &mut key) };
        if ret != 0 {
            Err(InternalKeyError { code: ret })
        } else {
            Ok(AesKeyDecrypt(key))
        }
    }
}

pub struct AesKeyEncrypt(AesKeyFfi);

impl AesKeyEncrypt {
    pub fn new(key_data: &[u8]) -> Result<AesKeyEncrypt, InternalKeyError> {
        let mut key = AesKeyFfi::new();
        let ret = unsafe { AES_set_encrypt_key(key_data.as_ptr(), 128, &mut key) };
        if ret != 0 {
            Err(InternalKeyError { code: ret })
        } else {
            Ok(AesKeyEncrypt(key))
        }
    }
}

pub fn aes_encrypt(data_in: &[u8; 16], data_out: &mut [u8; 16], key: &AesKeyEncrypt) {
    unsafe {
        AES_encrypt(data_in.as_ptr(), data_out.as_mut_ptr(), &key.0);
    }
}

pub fn aes_decrypt(data_in: &[u8; 16], data_out: &mut [u8; 16], key: &AesKeyDecrypt) {
    unsafe {
        AES_decrypt(data_in.as_ptr(), data_out.as_mut_ptr(), &key.0);
    }
}

#[link(name = "crypto")]
extern "C" {
    fn AES_set_encrypt_key(userKey: *const u8, bits: c_int, key: *mut AesKeyFfi) -> c_int;

    fn AES_set_decrypt_key(userKey: *const u8, bits: c_int, key: *mut AesKeyFfi) -> c_int;

    fn AES_encrypt(data_in: *const u8, data_out: *mut u8, key: *const AesKeyFfi) -> c_void;

    fn AES_decrypt(data_in: *const u8, data_out: *mut u8, key: *const AesKeyFfi) -> c_void;
}

#[cfg(test)]
mod tests {
    use super::{
        aes_decrypt, aes_encrypt, AES_decrypt, AES_encrypt, AES_set_decrypt_key,
        AES_set_encrypt_key, AesKeyDecrypt, AesKeyEncrypt, AesKeyFfi,
    };

    #[test]
    fn test_ffi() {
        let key_str = b"YELLOW SUBMARINE";
        let plaintext = b"MELLOW PREMARINE";
        let mut ciphertext = [0u8; 16];
        let mut decoded_ciphertext = [0u8; 16];

        let mut key_encrypt = AesKeyFfi::new();
        let mut key_decrypt = AesKeyFfi::new();
        unsafe {
            assert_eq!(
                0,
                AES_set_encrypt_key(key_str.as_ptr(), 128, &mut key_encrypt)
            );
            assert_eq!(
                0,
                AES_set_decrypt_key(key_str.as_ptr(), 128, &mut key_decrypt)
            );
            AES_encrypt(plaintext.as_ptr(), ciphertext.as_mut_ptr(), &key_encrypt);
            AES_decrypt(
                ciphertext.as_ptr(),
                decoded_ciphertext.as_mut_ptr(),
                &key_decrypt,
            );
        }
        assert_eq!(plaintext, &decoded_ciphertext);
        assert_ne!(plaintext, &ciphertext);
    }

    #[test]
    fn test_interface() {
        let key_str = b"YELLOW SUBMARINE";
        let plaintext = b"MELLOW TANGERINE";
        let mut ciphertext = [0u8; 16];
        let mut decoded_ciphertext = [0u8; 16];
        let key_encrypt = AesKeyEncrypt::new(key_str).unwrap();
        let key_decrypt = AesKeyDecrypt::new(key_str).unwrap();
        aes_encrypt(&plaintext, &mut ciphertext, &key_encrypt);
        aes_decrypt(&ciphertext, &mut decoded_ciphertext, &key_decrypt);

        assert_eq!(plaintext, &decoded_ciphertext);
        assert_ne!(plaintext, &ciphertext);
    }
}
