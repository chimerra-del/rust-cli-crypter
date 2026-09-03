use crate::alg::BlockCipher;

fn padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = if data.len() % block_size == 0 {
        block_size
    } else {
        block_size - (data.len() % block_size)
    };
    let mut result = data.to_vec();
    result.extend(vec![padding_len as u8; padding_len]);
    result
}

pub fn encrypt_ecb(cipher: &dyn BlockCipher, data: &[u8]) -> Vec<u8> {
    let block_size = cipher.block_size();
    let padded_data = padding(data, block_size);
    
    let mut ciphertext = Vec::new();
    for chunk in padded_data.chunks_exact(block_size) {
        let encrypted = cipher.encrypt_block(chunk);
        ciphertext.extend_from_slice(&encrypted);
    }
    
    ciphertext
}