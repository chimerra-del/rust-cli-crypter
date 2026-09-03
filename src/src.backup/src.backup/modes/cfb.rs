use crate::alg::BlockCipher;

fn xor_blocks(block_a: &[u8], block_b: &[u8]) -> Vec<u8> {
    block_a
        .iter()
        .zip(block_b.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

pub fn encrypt_cfb(cipher: &dyn BlockCipher, data: &[u8], iv: &[u8]) -> Vec<u8> {
   // Регистр сдвига
   // Инициализируем всё
   let block_size = cipher.block_size();
   let mut shift_register = iv.to_vec(); // Копируем IV
   let mut ciphertext = Vec::new();
   let mut block = [0u8; 16];
   // Заполняем остаток нулями
   plaintext[8..].fill(0);

   for i in 0..plaintext.len() {
     // Шифруем текущий регистр сдвига
     let mut cipherblock = cipher.encrypt_block(&shift_register)
     let gamma_byte = block[0];
     let cipher_byte = plaintext_byte ^ gamma_byte;
        ciphertext.push(cipher_byte);

        // Сдвигаем регистр и добавляем новый байт зашифрованного текста
        shift_register.remove(0);
        shift_register.push(cipher_byte);
   }
}