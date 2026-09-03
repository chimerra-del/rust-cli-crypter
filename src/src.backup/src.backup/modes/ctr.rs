use crate::alg::BlockCipher;

fn xor_blocks(block_a: &[u8], block_b: &[u8]) -> Vec<u8> {
    block_a
        .iter()
        .zip(block_b.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

pub fn encrypt_ctr(cipher: &dyn BlockCipher, data: &[u8], iv: &[u8], key: &[u8; 16]) -> Vec<u8> {
   // Инициализируем всё
   // На самом деле это state, но назовём plaintext для удобства cipher()
   let mut plaintext = [0u8; 16];
   plaintext[..8].copy_from_slice(iv); // iv должен быть 8 байт
   let mut counter = 0u64;
   let block_size = cipher.block_size();
   // Заполняем остаток нулями
   plaintext[8..].fill(0);
  
   // Шифрование
   // CTR не нужен паддинг
   let mut ciphertext = Vec::with_capacity(data.len());
     for chunk in data.chunks(block_size) {
       plaintext[block_size - 8..].copy_from_slice(&counter.to_be_bytes());       
        // Шифруем счётчик
        let keystream_block = cipher.cipher(&plaintext, key);       
        // XOR с данными
        let encrypted_chunk = xor_blocks(chunk, &keystream_block[..chunk.len()]);
        ciphertext.extend_from_slice(&encrypted_chunk);

        // Счётчик
        counter += 1;
     }
    
    ciphertext
}