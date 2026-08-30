// Custom AES вручную
// Теперь я собственнлсть глобальных мафиозных синдикатов
use super::block_cipher::BlockCipher;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]; // Взял из таблицы NIST
const NUM_ROUNDS: u8 = 10;
type State = [[u8; 4]; 4];

// Повтори такое же для других шифров, срочно
pub struct AES {
    key: [u8; 16],
}

impl AES {
    pub fn new(key: [u8; 16]) -> Self {
        AES { key }
    }
}

impl BlockCipher for AES {
    fn block_size(&self) -> usize {
        16
    }
    
    fn encrypt_block(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut block = [0u8; 16];
        block.copy_from_slice(plaintext);
        cipher(&block, &self.key).to_vec()
    }
    
    fn decrypt_block(&self, ciphertext: &[u8]) -> Vec<u8> {
        // TODO: Реализовать расшифровку
        todo!("Implement AES decryption")
    }
    
    fn name(&self) -> &str {
        "AES-128"
    }
}

// Эта функция преобрезует текст в матрицу 4х4
/// Вайбкод
fn load_state(plaintext: &[u8; 16]) -> State {
    let mut state: State = [[0; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = plaintext[i + j * 4];
        }
    }
    state
}

/// Вайбкод
fn store_state(state: &State, output: &mut [u8; 16]) {
    for i in 0..4 {
        for j in 0..4 {
            output[i + j * 4] = state[i][j];
        }
    }
}

// Расширить ключ до 256 бит
// Инцииализировать State в функции load_state()
pub fn cipher(plaintext: &[u8; 16], key: &[u8; 16]) -> [u8; 16] {
  // загружаем состоянние
  let mut state = load_state(plaintext);
  // расширяем ключ
  let expanded_key = key_expansion(key);
  
  // Первый раундовый ключ
  add_round_key(&mut state, &expanded_key[0..16]);

  for round in 1..NUM_ROUNDS as usize {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &expanded_key[round * 16..(round + 1) * 16]);
  }

  sub_bytes(&mut state);
  shift_rows(&mut state);
  add_round_key(&mut state, &expanded_key[NUM_ROUNDS as usize * 16..]);
  
  let mut output = [0u8; 16];
  store_state(&state, &mut output);
  output
}

fn sub_bytes(state: &mut State) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = SBOX[state[i][j] as usize];
        }
    }
}

fn shift_rows(state: &mut State) {
    state[1].rotate_left(1);
    state[2].rotate_left(2);
    state[3].rotate_left(3);
}

fn mix_columns(state: &mut State) {
  /* Умножение в поле Галуа GF(2^8) и сложение (XOR)
        State[0][c] = Multiply(0x02, s0) ^ Multiply(0x03, s1) ^ s2 ^ s3
        State[1][c] = s0 ^ Multiply(0x02, s1) ^ Multiply(0x03, s2) ^ s3
        State[2][c] = s0 ^ s1 ^ Multiply(0x02, s2) ^ Multiply(0x03, s3)
        State[3][c] = Multiply(0x03, s0) ^ s1 ^ s2 ^ Multiply(0x02, s3)
  */
  // ID 0
    for c in 0..4 {
        let s0 = state[0][c];
        let s1 = state[1][c];
        let s2 = state[2][c];
        let s3 = state[3][c];

        state[0][c] = multiply(0x02, s0) ^ multiply(0x03, s1) ^ s2 ^ s3;
        state[1][c] = s0 ^ multiply(0x02, s1) ^ multiply(0x03, s2) ^ s3;
        state[2][c] = s0 ^ s1 ^ multiply(0x02, s2) ^ multiply(0x03, s3);
        state[3][c] = multiply(0x03, s0) ^ s1 ^ s2 ^ multiply(0x02, s3);
    }
    }

// Поля Галуа
fn multiply(num: u8, byte: u8) -> u8 {
    if num == 0x01 {
        return byte;
    } else if num == 0x02 {
        let temp = byte << 1;
        if (byte & 0x80) != 0 {
            return (temp ^ 0x1b) & 0xff;
        } else {
            return temp & 0xff;
        }
    } else if num == 0x03 {
        return multiply(0x02, byte) ^ byte;
    }
    byte
}

fn add_round_key(state: &mut State, round_key: &[u8]) {
    for col in 0..4 {
        for row in 0..4 {
            state[row][col] ^= round_key[row + col * 4];
        }
    }
}

// Раасширение ключа
fn key_expansion(key: &[u8; 16]) -> Vec<u8> {
    let mut w = Vec::new();
    for i in 0..4 {
        w.push(key[4 * i]);
        w.push(key[4 * i + 1]);
        w.push(key[4 * i + 2]);
        w.push(key[4 * i + 3]);
    }
    
    while w.len() < 44 * 4 {
        let mut temp = [w[w.len() - 4], w[w.len() - 3], w[w.len() - 2], w[w.len() - 1]];     
        if (w.len() / 4) % 4 == 0 {
            temp = sub_word(rot_word(temp));
        }        
        w.push(temp[0]);
        w.push(temp[1]);
        w.push(temp[2]);
        w.push(temp[3]);
    }
    
    w
}

// Извороты 1 с SBOX
fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ]
}

// Извороты 2 с SBOX
fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}