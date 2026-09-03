pub struct Salsa20 {
    state: [u32; 16],
}

impl Salsa20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 8]) -> Self {
        let mut state = [0u32; 16];
        state[0]  = u32::from_le_bytes(*b"expa");
        state[5]  = u32::from_le_bytes(*b"nd 3");
        state[10] = u32::from_le_bytes(*b"2-by");
        state[15] = u32::from_le_bytes(*b"te k");
        state[1]  = u32::from_le_bytes(key[0..4].try_into().unwrap());
        state[2]  = u32::from_le_bytes(key[4..8].try_into().unwrap());
        state[3]  = u32::from_le_bytes(key[8..12].try_into().unwrap());
        state[4]  = u32::from_le_bytes(key[12..16].try_into().unwrap());
        state[11] = u32::from_le_bytes(key[16..20].try_into().unwrap());
        state[12] = u32::from_le_bytes(key[20..24].try_into().unwrap()); 
        state[13] = u32::from_le_bytes(key[24..28].try_into().unwrap());
        state[14] = u32::from_le_bytes(key[28..32].try_into().unwrap());
        state[6]  = 0;
        state[7]  = 0;
        state[8]  = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
        state[9]  = u32::from_le_bytes(nonce[4..8].try_into().unwrap());

        Salsa20 { state }
    }

    #[inline]
    fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
        x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
        x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
        x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
    }

    fn generate_block(&self) -> [u8; 64] {
        let mut x = self.state;

        for _ in 0..10 {
            Self::quarter_round(&mut x, 0, 4, 8, 12);
            Self::quarter_round(&mut x, 5, 9, 13, 1);
            Self::quarter_round(&mut x, 10, 14, 2, 6);
            Self::quarter_round(&mut x, 15, 3, 7, 11);
            Self::quarter_round(&mut x, 0, 1, 2, 3);
            Self::quarter_round(&mut x, 5, 6, 7, 4);
            Self::quarter_round(&mut x, 10, 11, 8, 9);
            Self::quarter_round(&mut x, 15, 12, 13, 14);
        }

        let mut keystream = [0u8; 64];
        for i in 0..16 {
            let word = x[i].wrapping_add(self.state[i]);
            keystream[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        keystream
    }

    fn increment_counter(&mut self) {
        self.state[6] = self.state[6].wrapping_add(1);
        if self.state[6] == 0 {
            self.state[7] = self.state[7].wrapping_add(1);
        }
    }

    pub fn process(&mut self, data: &mut [u8]) {
        let mut i = 0;
        while i < data.len() {
            let keystream = self.generate_block();
            let chunk_size = std::cmp::min(data.len() - i, 64);

            for j in 0..chunk_size {
                data[i + j] ^= keystream[j];
            }

            i += chunk_size;
            self.increment_counter();
        }
    }
}

pub fn salsa20_encrypt(data: &mut Vec<u8>, key: &[u8; 32], nonce: &[u8; 8]) {
    let mut cipher = Salsa20::new(key, nonce);
    cipher.process(data);
}