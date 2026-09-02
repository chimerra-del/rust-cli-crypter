// Custom RC5 Rust
// Стань единой с моею тенью
pub fn rc5_encrypt(s: &[u8], r: u8, plaintext: &[u8], out: &mut [u8]) { 
    let mut a = (plaintext[0] & 0xFF) as u32;  // Удалил дублирование
    a |= ((plaintext[1] & 0xFF) as u32) << 8;
    a |= ((plaintext[2] & 0xFF) as u32) << 16;
    a |= ((plaintext[3] & 0xFF) as u32) << 24;

    let mut b = (plaintext[4] & 0xFF) as u32;
    b |= ((plaintext[5] & 0xFF) as u32) << 8;
    b |= ((plaintext[6] & 0xFF) as u32) << 16;
    b |= ((plaintext[7] & 0xFF) as u32) << 24;
    
    a = a.wrapping_add(s[0] as u32); 
    b = b.wrapping_add(s[1] as u32);
    
    for i in 0..(r as usize) {
        a ^= b;
        a = a.rotate_left(b as u32).wrapping_add(s[2 * i] as u32);
        b ^= a;
        b = b.rotate_left(a as u32).wrapping_add(s[2 * i + 1] as u32);
    }

    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
}