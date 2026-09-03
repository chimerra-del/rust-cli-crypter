pub trait BlockCipher: Send + Sync {
    fn block_size(&self) -> usize;
    fn encrypt_block(&self, plaintext: &[u8]) -> Vec<u8>;
    fn decrypt_block(&self, ciphertext: &[u8]) -> Vec<u8>;
    fn name(&self) -> &str;
}
