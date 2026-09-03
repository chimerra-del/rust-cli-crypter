use crate::alg::block_cipher::BlockCipher;
use crate::alg::camelia::CamelliaKey;

/// Обёртка для AES с поддержкой BlockCipher
pub struct AesCipher {
    key: [u8; 16],
}

impl AesCipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() < 16 {
            return Err("AES ключ должен быть минимум 16 байт".to_string());
        }
        let mut key_array = [0u8; 16];
        key_array.copy_from_slice(&key[0..16]);
        Ok(AesCipher { key: key_array })
    }
}

impl BlockCipher for AesCipher {
    fn block_size(&self) -> usize {
        16
    }
    
    fn encrypt_block(&self, plaintext: &[u8]) -> Vec<u8> {
        if plaintext.len() < 16 {
            return vec![0u8; 16];
        }
        let block = <[u8; 16]>::try_from(&plaintext[0..16]).unwrap();
        crate::alg::cipher(&block, &self.key).to_vec()
    }
    
    fn decrypt_block(&self, ciphertext: &[u8]) -> Vec<u8> {
        if ciphertext.len() < 16 {
            return vec![0u8; 16];
        }
        let block = <[u8; 16]>::try_from(&ciphertext[0..16]).unwrap();
        crate::alg::inv_cipher(&block, &self.key).to_vec()
    }
    
    fn name(&self) -> &str {
        "AES-128"
    }
}

/// Обёртка для Camellia с поддержкой BlockCipher
pub struct CamelliaCipher {
    key_schedule: CamelliaKey,
}

impl CamelliaCipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() < 32 {
            return Err("Camellia ключ должен быть минимум 32 байт".to_string());
        }
        let key_array: [u8; 32] = key[0..32].try_into()
            .map_err(|_| "Неверная длина ключа".to_string())?;
        let key_schedule = crate::alg::key_schedule(&key_array);
        Ok(CamelliaCipher { key_schedule })
    }
}

impl BlockCipher for CamelliaCipher {
    fn block_size(&self) -> usize {
        16
    }
    
    fn encrypt_block(&self, plaintext: &[u8]) -> Vec<u8> {
        if plaintext.len() < 16 {
            return vec![0u8; 16];
        }
        let block = <[u8; 16]>::try_from(&plaintext[0..16]).unwrap();
        crate::alg::camelia_encrypt(&block, &self.key_schedule).to_vec()
    }
    
    fn decrypt_block(&self, ciphertext: &[u8]) -> Vec<u8> {
        if ciphertext.len() < 16 {
            return vec![0u8; 16];
        }
        let block = <[u8; 16]>::try_from(&ciphertext[0..16]).unwrap();
        crate::alg::camelia_decrypt(&block, &self.key_schedule).to_vec()
    }
    
    fn name(&self) -> &str {
        "Camellia-256"
    }
}

/// Обёртка для ChaCha20 с поддержкой BlockCipher
pub struct ChaCha20Cipher {
    key: [u8; 32],
}

impl ChaCha20Cipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() < 32 {
            return Err("ChaCha20 ключ должен быть минимум 32 байт".to_string());
        }
        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&key[0..32]);
        Ok(ChaCha20Cipher { key: key_array })
    }
}

impl BlockCipher for ChaCha20Cipher {
    fn block_size(&self) -> usize {
        64  // ChaCha20 генерирует 64 байта за раунд
    }
    
    fn encrypt_block(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = [0u8; 12];
        crate::alg::chacha20_encrypt(&self.key, 0, &nonce, plaintext)
    }
    
    fn decrypt_block(&self, ciphertext: &[u8]) -> Vec<u8> {
        let nonce = [0u8; 12];
        crate::alg::chacha20_encrypt(&self.key, 0, &nonce, ciphertext)
    }
    
    fn name(&self) -> &str {
        "ChaCha20"
    }

    /*
    fn is_deterministic(&self) -> bool {
        false  // ChaCha20 требует nonce
    }
    */
}
pub struct XteaCipher {
    key: [u32; 4],
}

impl XteaCipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() < 16 {
            return Err("XTEA ключ должен быть 16 байт".to_string());
        }
        let mut key_array = [0u32; 4];
        for i in 0..4 {
            key_array[i] = u32::from_le_bytes([
                key[i*4],
                key[i*4 + 1],
                key[i*4 + 2],
                key[i*4 + 3],
            ]);
        }
        Ok(XteaCipher { key: key_array })
    }
}

impl BlockCipher for XteaCipher {
    fn block_size(&self) -> usize {
        8
    }
    
    fn encrypt_block(&self, plaintext: &[u8]) -> Vec<u8> {
        if plaintext.len() < 8 {
            return vec![0u8; 8];
        }
        let mut block = [0u32; 2];
        block[0] = u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        block[1] = u32::from_le_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        
        crate::alg::xtea_encrypt(&mut block, &self.key);
        
        let mut result = Vec::with_capacity(8);
        result.extend_from_slice(&block[0].to_le_bytes());
        result.extend_from_slice(&block[1].to_le_bytes());
        result
    }
    
    fn decrypt_block(&self, ciphertext: &[u8]) -> Vec<u8> {
        if ciphertext.len() < 8 {
            return vec![0u8; 8];
        }
        let mut block = [0u32; 2];
        block[0] = u32::from_le_bytes([ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]]);
        block[1] = u32::from_le_bytes([ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7]]);
        
        crate::alg::xtea_decrypt(&mut block, &self.key);
        
        let mut result = Vec::with_capacity(8);
        result.extend_from_slice(&block[0].to_le_bytes());
        result.extend_from_slice(&block[1].to_le_bytes());
        result
    }
    
    fn name(&self) -> &str {
        "XTEA"
    }
}
