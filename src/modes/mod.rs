use std::fmt::Debug;
use super::CipherError;

pub mod ecb;
pub mod cbc;
pub mod cfb;
pub mod ctr;
pub mod gcm;
pub mod ccm;


pub trait BlockCipher: Send + Sync + Debug {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, CipherError>;
    fn decrypt_block(&self, block: &[u8]) -> Result<Vec<u8>, CipherError>;
}

