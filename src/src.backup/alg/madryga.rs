
const BLOCK_SIZE: usize = 8;
const NUM_ROUNDS: usize = 8;

const RANDOM_CONSTANT: u64 = 0x0f1e2d3c4b5a6978;

// Алгоритм использует 2 вложенных цикла
fn rotate_left_16(value: u16, bits: u32) -> u16 {
    // left 
    (value << bits) | (value >> ((16 - bits) % 16))
}

fn rotate_right_16(value: u16, bits: u32) -> u16 {
   // right
   (value >> bits) | (value << ((16 - bits) % 16))
}

pub fn madryga_encrypt(data: &mut [u8], key: u64){
    let data_len = data.len();
    
    for i in(0..data_len - 1).rev(){
        let start = i % data_len;
        let mid = (i + 1) % data_len;
        let end = (i + 2) % data_len;

        let rotation_bits = (data[end] & 0x07) as u32;

        let mut temp: u16 = ((data[mid] as u16) << 8) | (data[start] as u16);

        temp = rotate_left_16(temp, rotation_bits);
        data[start] = temp as u8;
        data[mid] = (temp >> 8) as u8;

        data[end] ^= (key & 0xFF) as u8;
    }
}