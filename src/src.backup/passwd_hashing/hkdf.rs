use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let salt = if salt.is_empty() {
        &[0u8; 32] // 32 байта нулей для SHA-256
    } else {
        salt
    };
    
    let mut mac = HmacSha256::new_from_slice(salt)
        .expect("HMAC может принимать ключ любой длины");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

pub fn hkdf_expand(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hash_len = 32; // Для SHA-256
    let max_len = hash_len * 255;
    
    assert!(
        length <= max_len,
        "Запрашиваемая длина {} превышает максимальную {}",
        length, max_len
    );
    
    let n_blocks = (length + hash_len - 1) / hash_len; // Округление вверх
    let mut result = Vec::with_capacity(length);
    let mut previous = Vec::new(); // T(0)
    
    for i in 1..=n_blocks {
        let mut mac = HmacSha256::new_from_slice(prk)
            .expect("PRK должен быть корректным ключом");
        
        // T(i) = HMAC-Hash(PRK, T(i-1) + info + i)
        mac.update(&previous);
        mac.update(info);
        mac.update(&[i as u8]); // счетчик
        
        let t_i = mac.finalize().into_bytes().to_vec();
        previous = t_i.clone();
        let remaining = length - result.len();
        let take = std::cmp::min(remaining, hash_len);
        result.extend_from_slice(&t_i[..take]);
    }
    
    result
}

/// Полный HKDF процесс (Extract + Expand)
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}
