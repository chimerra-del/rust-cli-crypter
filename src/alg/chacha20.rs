// ТЕПЕРЬ Я СОБСТВЕННОСТЬ КАРТЕЛЯ
use std::fmt::Write;

// const SIGMA: &str = "expand 32 byte key";
// штука сверху багается, лучше битами
const SIGMA: [u32; 4] = [
    0x61707865,  // "expa"
    0x3320646e,  // "nd 3"
    0x79622d32,  // "2-by"
    0x6b206574,  // "te k"
];

// Четвертт раунда(кручение)
pub fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_right(16);  
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_right(12);   
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_right(8);    
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_right(7);

    /*  a += b; d ^= a; d <<<= 16;
        c += d; b ^= c; b <<<= 12;
        a += b; d ^= a; d <<<= 8;
        c += d; b ^= c; b <<<= 7;
    */
}

pub fn inner_block(state: &mut [u32; 16]) {
    // На столбцах
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);

    // На диагоналях
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

pub fn serialize(state: [u32; 16]) -> Vec<u8> {
    let mut result = Vec::with_capacity(64);
    for word in state {
        result.extend_from_slice(&word.to_le_bytes());
    }
    result
}

/* chacha20_block(key, counter, nonce):
         состояние = константы | ключ | счетчик | nonce
         начальное_состояние = состояние
         для i=1 до 10
            inner_block(state)
            конец
         состояние += начальное состояние
         return serialize(state)
         конец
*/

pub fn chacha20_block(key: &[u8; 32], counter: u64, nonce: &[u8; 12]) -> Vec<u8> {
    let mut state: [u32; 16] = [0; 16];
    state[0..4].copy_from_slice(&SIGMA);
    
    for i in 0..8 {
        let start = i * 4;
        state[4 + i] = u32::from_le_bytes([
            key[start],
            key[start + 1],
            key[start + 2],
            key[start + 3],
        ]);
    }
    
    state[12] = (counter & 0xFFFFFFFF) as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[15] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    
    let nonce_part1 = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    let nonce_part2 = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    let nonce_part3 = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    
    state[13] = (counter >> 32) as u32;
    state[14] = nonce_part1;
    state[15] = nonce_part2;
    let start_state = state;

    for _ in 0..10 {
        inner_block(&mut state);
    }
    for i in 0..16 {
        state[i] = state[i].wrapping_add(start_state[i]);
    }
    
    serialize(state)
}

/*
chacha20_encrypt(key, counter, nonce, data):
        для j = 0 до floor(len(data)/64)-1
           key_stream = chacha20_block(key, counter+j, nonce)
           блок = простой текст[(j*64)..(j*64+63)]
           encrypted_message += block ^ key_stream
           конец
        если ((len(data) % 64) != 0)
           j = floor(len(data)/64)
           key_stream = chacha20_block(key, counter+j, nonce)
           блок = простой текст[(j*64)..len(простой текст)-1]
           encrypted_message += (block^key_stream)[0..len(data)%64]
           конец
        return encrypted_message
        конец
*/

pub fn chacha20_encrypt(key: &[u8; 32], counter: u64, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let mut encrypted_message: Vec<u8> = Vec::new();
    for j in 0..(data.len() / 64) {
        let key_stream = chacha20_block(key, counter + j as u64, nonce);
        let block = &data[(j * 64)..((j + 1) * 64)];
        
        // XOR
        for (x, y) in block.iter().zip(key_stream.iter()) {
            encrypted_message.push(x ^ y);
        }
    }
    
    if data.len() % 64 != 0 {
        let j = data.len() / 64;
        let key_stream = chacha20_block(key, counter + j as u64, nonce);
        let block = &data[(j * 64)..];
        
        for (x, y) in block.iter().zip(key_stream.iter()) {
            encrypted_message.push(x ^ y);
        }
    }
    
    encrypted_message
}