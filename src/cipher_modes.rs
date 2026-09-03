use crate::alg::block_cipher::BlockCipher;

pub struct EcbMode;

impl EcbMode {
    pub fn encrypt(
        cipher: &dyn BlockCipher,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let block_size = cipher.block_size();
        let mut ciphertext = Vec::new();
        
        for chunk in plaintext.chunks(block_size) {
            let mut padded = vec![0u8; block_size];
            padded[..chunk.len()].copy_from_slice(chunk);
            let encrypted = cipher.encrypt_block(&padded);
            ciphertext.extend_from_slice(&encrypted);
        }
        
        Ok(ciphertext)
    }
    
    pub fn decrypt(
        cipher: &dyn BlockCipher,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let block_size = cipher.block_size();
        if ciphertext.len() % block_size != 0 {
            return Err("Длина шифротекста должна быть кратна размеру блока".to_string());
        }
        
        let mut plaintext = Vec::new();
        for chunk in ciphertext.chunks(block_size) {
            let decrypted = cipher.decrypt_block(chunk);
            plaintext.extend_from_slice(&decrypted);
        }
        
        Ok(plaintext)
    }
}

pub struct CbcMode {
    iv: Vec<u8>,
}

impl CbcMode {
    pub fn new(iv: Vec<u8>) -> Result<Self, String> {
        Ok(CbcMode { iv })
    }
    
    pub fn encrypt(
        &self,
        cipher: &dyn BlockCipher,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let block_size = cipher.block_size();
        
        if self.iv.len() != block_size {
            return Err(format!("IV должен быть размером {}", block_size));
        }
        
        let mut ciphertext = Vec::new();
        let mut previous_block = self.iv.clone();
        
        for chunk in plaintext.chunks(block_size) {
            // Добавляем PKCS7 padding
            let mut padded = vec![0u8; block_size];
            padded[..chunk.len()].copy_from_slice(chunk);
            if chunk.len() < block_size {
                let padding_len = block_size - chunk.len();
                for i in chunk.len()..block_size {
                    padded[i] = padding_len as u8;
                }
            }
            
            // XOR с предыдущим блоком
            for i in 0..block_size {
                padded[i] ^= previous_block[i];
            }
            
            // Шифруем
            let encrypted = cipher.encrypt_block(&padded);
            ciphertext.extend_from_slice(&encrypted);
            previous_block = encrypted.clone();
        }
        
        Ok(ciphertext)
    }
    
    pub fn decrypt(
        &self,
        cipher: &dyn BlockCipher,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let block_size = cipher.block_size();
        
        if ciphertext.len() % block_size != 0 {
            return Err("Длина шифротекста должна быть кратна размеру блока".to_string());
        }
        
        let mut plaintext = Vec::new();
        let mut previous_block = self.iv.clone();
        
        for chunk in ciphertext.chunks(block_size) {
            let decrypted = cipher.decrypt_block(chunk);
            
            // XOR с предыдущим блоком
            let mut xored = Vec::new();
            for i in 0..block_size {
                xored.push(decrypted[i] ^ previous_block[i]);
            }
            
            plaintext.extend_from_slice(&xored);
            previous_block = chunk.to_vec();
        }
        
        // Удаляем PKCS7 padding
        if let Some(&padding_len) = plaintext.last() {
            let padding_len = padding_len as usize;
            if padding_len > 0 && padding_len <= block_size {
                plaintext.truncate(plaintext.len() - padding_len);
            }
        }
        
        Ok(plaintext)
    }
}

/// CTR  режим счётчика для поточного шифрования
pub struct CtrMode {
    nonce: Vec<u8>,
    counter: u64,
}

impl CtrMode {
    pub fn new(nonce: Vec<u8>) -> Result<Self, String> {
        Ok(CtrMode { nonce, counter: 0 })
    }
    
    pub fn encrypt(
        &mut self,
        cipher: &dyn BlockCipher,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let block_size = cipher.block_size();
        
        if self.nonce.len() + 8 > block_size {
            return Err("Nonce слишком длинный для режима CTR".to_string());
        }
        
        let mut ciphertext = Vec::new();
        
        for chunk in plaintext.chunks(block_size) {
            // Строим блок счётчика
            let mut counter_block = vec![0u8; block_size];
            counter_block[..self.nonce.len()].copy_from_slice(&self.nonce);
            counter_block[self.nonce.len()..self.nonce.len() + 8]
                .copy_from_slice(&self.counter.to_le_bytes());
            
            // Шифруем счётчик
            let keystream = cipher.encrypt_block(&counter_block);
            
            // XOR с данными
            for i in 0..chunk.len() {
                ciphertext.push(chunk[i] ^ keystream[i]);
            }
            
            self.counter += 1;
        }
        
        Ok(ciphertext)
    }
    
    pub fn decrypt(
        &mut self,
        cipher: &dyn BlockCipher,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        // CTR: encryption == decryption
        self.encrypt(cipher, ciphertext)
    }
}

/// GCM - аутентифицированное шифрование
pub struct GcmMode {
    nonce: Vec<u8>,
}

impl GcmMode {
    pub fn new(nonce: Vec<u8>) -> Result<Self, String> {
        if nonce.is_empty() {
            return Err("Nonce не может быть пустым".to_string());
        }
        Ok(GcmMode { nonce })
    }
    
    pub fn encrypt(
        &self,
        cipher: &dyn BlockCipher,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        let block_size = cipher.block_size();
        
        // Используем CTR для шифрования
        let mut ctr = CtrMode::new(self.nonce.clone())?;
        let mut ciphertext = Vec::new();
        
        for chunk in plaintext.chunks(block_size) {
            let mut counter_block = vec![0u8; block_size];
            counter_block[..self.nonce.len()].copy_from_slice(&self.nonce);
            counter_block[self.nonce.len()..self.nonce.len() + 8]
                .copy_from_slice(&ctr.counter.to_le_bytes());
            
            let keystream = cipher.encrypt_block(&counter_block);
            
            for i in 0..chunk.len() {
                ciphertext.push(chunk[i] ^ keystream[i]);
            }
            
            ctr.counter += 1;
        }
        
        // Генерируем простой тег (в реальности нужен GHASH)
        let mut tag = self.nonce.clone();
        for byte in &ciphertext {
            tag.push(*byte);
        }
        
        // Хешируем для получения тега
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};
        tag.hash(&mut hasher);
        let hash_value = hasher.finish();
        
        let tag_bytes = hash_value.to_le_bytes().to_vec();
        
        Ok((ciphertext, tag_bytes))
    }
}

/// Вспомогательная функция для выбора режима
pub fn create_mode(
    mode_name: &str,
    iv_or_nonce: Option<Vec<u8>>,
) -> Result<String, String> {
    match mode_name.to_lowercase().as_str() {
        "ecb" => Ok("ecb".to_string()),
        "cbc" => {
            if iv_or_nonce.is_none() {
                return Err("CBC требует IV".to_string());
            }
            Ok("cbc".to_string())
        }
        "ctr" => {
            if iv_or_nonce.is_none() {
                return Err("CTR требует nonce".to_string());
            }
            Ok("ctr".to_string())
        }
        "gcm" => {
            if iv_or_nonce.is_none() {
                return Err("GCM требует nonce".to_string());
            }
            Ok("gcm".to_string())
        }
        _ => Err(format!("Неизвестный режим: {}", mode_name)),
    }
}
