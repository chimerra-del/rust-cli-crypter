// Теперь ты собственность картеля
pub fn xtea_encrypt(v: &mut [u32; 2], k: &[u32; 4]) {
    let mut v0: u32 = v[0];
    let mut v1: u32 = v[1];
    let mut sum: u32 = 0;
    let delta: u32 = 0x9E3779B9;

    for _ in 0..32 {
        v0 = v0.wrapping_add(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ (sum.wrapping_add(k[(sum & 3) as usize]))
        );
        sum = sum.wrapping_add(delta);
        v1 = v1.wrapping_add(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)) ^ (sum.wrapping_add(k[((sum >> 11) & 3) as usize]))
        );
    }

    v[0] = v0;
    v[1] = v1;
}