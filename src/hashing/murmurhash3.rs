const C1: u32 = 0xcc9e2d51;
const C2: u32 = 0x1b873593;

pub fn murmur(seed: u32, data: &[u8]) -> u32 {
    let mut h1 = seed;
    let data_len = data.len();
    for chunk in data.chunks_exact(4) {
        let mut k1 = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    let remainder = data.len() % 4;
    if remainder > 0 {
        let tail = &data[data.len() - remainder..];
        let mut k1: u32 = 0;
        
        match remainder {
            3 => {
                k1 |= (tail[2] as u32) << 16;
                k1 |= (tail[1] as u32) << 8;
                k1 |= tail[0] as u32;
            }
            2 => {
                k1 |= (tail[1] as u32) << 8;
                k1 |= tail[0] as u32;
            }
            1 => {
                k1 = tail[0] as u32;
            }
            _ => {}
        }
        
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(15);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }
    h1 ^= data_len as u32;
    fmix32(h1)
}

fn fmix32(mut h1: u32) -> u32 {
    h1 ^= h1 >> 15;
    h1 = h1.wrapping_mul(0x85ebca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2ae35);
    h1 ^= h1 >> 16;
    h1
}