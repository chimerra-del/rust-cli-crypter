use crate::alg::block_cipher::BlockCipher;
use crate::cipher_implementations::{AesCipher, CamelliaCipher, ChaCha20Cipher, XteaCipher};

/// Фабрика для создания шифров
pub struct CipherFactory;

impl CipherFactory {
    /// Создать шифр по названию алгоритма
    pub fn create_cipher(algorithm: &str, key: &[u8]) -> Result<Box<dyn BlockCipher>, String> {
        match algorithm.to_lowercase().as_str() {
            "aes" | "aes-128" => Ok(Box::new(AesCipher::new(key)?) as Box<dyn BlockCipher>),
            "camellia" | "camellia-256" => Ok(Box::new(CamelliaCipher::new(key)?) as Box<dyn BlockCipher>),
            "chacha20" => Ok(Box::new(ChaCha20Cipher::new(key)?) as Box<dyn BlockCipher>),
            "xtea" => Ok(Box::new(XteaCipher::new(key)?) as Box<dyn BlockCipher>),
            _ => Err(format!("Неизвестный алгоритм: {}", algorithm)),
        }
    }
}

/// Конфигурация для шифрования с режимом
pub struct EncryptionConfig {
    pub algorithm: String,
    pub mode: String,
    pub key: Vec<u8>,
    pub iv: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl EncryptionConfig {
    pub fn new(algorithm: String, mode: String, key: Vec<u8>) -> Self {
        EncryptionConfig {
            algorithm,
            mode,
            key,
            iv: None,
            nonce: None,
        }
    }
    
    /// Установить IV для режимов, требующих его (CBC, CFB, OFB)
    pub fn with_iv(mut self, iv: Vec<u8>) -> Self {
        self.iv = Some(iv);
        self
    }
    
    /// Установить nonce для режимов, требующих его (CTR, GCM, CCM)
    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }
}
