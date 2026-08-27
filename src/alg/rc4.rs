pub struct State {
    S: [u8; 256],
    i: u8,
    j: u8,
}

// Инициализация
pub fn rc4_init(key: &[u8]) -> State {
    let mut state = State {
        S: [0; 256],
        i: 0,
        j: 0,
    };
    
    for i in 0..256 {
        state.S[i] = i as u8;
    }
    
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(state.S[i]).wrapping_add(key[i % key.len()]);
        state.S.swap(i, j as usize);
    }
    
    state
}

// Шифрование
pub fn rc4_crypt(state: &mut State, data: &mut [u8]) {
    for k in 0..data.len() {
        state.i = state.i.wrapping_add(1);
        state.j = state.j.wrapping_add(state.S[state.i as usize]);
        state.S.swap(state.i as usize, state.j as usize);
        
        let idx = (state.S[state.i as usize] as usize + state.S[state.j as usize] as usize) % 256;
        let K = state.S[idx];
        data[k] ^= K;
    }
}