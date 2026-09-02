// Я ещё не собственность картеля
// C = (P + K) mod N
// Где: C — зашифрованная буква, P — исходная буква, K — буква ключа, mod — остаток от деления
// N - кол-во букв в Алфавите(Мы возьмём En)
pub fn viginere_encrypt(data: &str, key: &str, decrypt: bool) -> String {
    if key.is_empty() {
        return data.to_string();
    }

    data.chars()
        .enumerate()
        .map(|(i, byte)| {
            let key_byte = key.chars().nth(i % key.len()).unwrap();
            let shift = (key_byte as u32 - 'A' as u32) as u8;
            
            if byte.is_ascii_alphabetic() {
                let base = if byte.is_ascii_uppercase() { b'A' } else { b'a' } as u32;
                let offset = (byte as u32 - base) as u8;
                
                let new_offset = if decrypt {
                    offset.wrapping_sub(shift) % 26
                } else {
                    offset.wrapping_add(shift) % 26
                };
                
                (base as u8 + new_offset) as char
            } else {
                byte
            }
        })
        .collect()
}