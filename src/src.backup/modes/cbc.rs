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

fn xor_blocks(block_a: &[u8], block_b: &[u8]) -> Vec<u8> {
    block_a
        .iter()
        .zip(block_b.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

pub fn encrypt_cbc(cipher: &dyn BlockCipher, data: &[u8], iv: &[u8]) -> Vec<u8> {
    let block_size = cipher.block_size();
    assert_eq!(iv.len(), block_size, "IV размер должен быть {}", block_size);
    
    let padded_data = padding(data, block_size);
    let mut ciphertext = Vec::with_capacity(padded_data.len());
    let mut previous_block = iv.to_vec();
    
    for chunk in padded_data.chunks_exact(block_size) {
        let xored = xor_blocks(chunk, &previous_block);
        let encrypted_block = cipher.encrypt_block(&xored);
        ciphertext.extend_from_slice(&encrypted_block);
        previous_block = encrypted_block.clone();
    }
    
    ciphertext
}
