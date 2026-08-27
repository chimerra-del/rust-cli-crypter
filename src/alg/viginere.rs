// Я ещё не собственность картеля
// C = (P + K) mod N
// Где: C — зашифрованная буква, P — исходная буква, K — буква ключа, mod — остаток от деления
// N - кол-во букв в Алфавите(Мы возьмём En)
pub fn viginere_encrypt(data: &str, key: &str) {
  // text[i] = (c - base + (toupper(k) - 'A')) % 26 + base
  if key.is_empty() {
        return data.to_vec();
    }

    data.iter()
        .enumerate()
        .map(|(i, &byte)| {
            let key_byte = key[i % key.len()];
            if decrypt {
                byte.wrapping_sub(key_byte)
            } else {
                // Сложение по модулю 256 для шифрования
                byte.wrapping_add(key_byte)
            }
        })
        .collect()
}