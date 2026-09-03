// Sha-1 rust
// secure

const SHA1_K: [u32; 80] = {
    let mut k = [0u32; 80];
    let mut i = 0;
    while i < 20 { k[i] = 0x5A827999; i += 1; }
    while i < 40 { k[i] = 0x6ED9EBA1; i += 1; }
    while i < 60 { k[i] = 0x8F1BBCDC; i += 1; }
    while i < 80 { k[i] = 0xCA62C1D6; i += 1; }
    
    k
};

fn sha128_hash(data: &[u8]) {
  let data_len: u64 = data.len();
  let mut buffer = vec![0u8; data_len + 8];
  buffer[..data_len].copy_from_slice(data);
  let h1: u32 = SHA1_K;
  let h2: u32 = SHA1_K;
  let h3: u32 = SHA1_K;
  let h4: u32 = SHA1_K;  
  data.wrapping_add(0x80);
  let pad_len = (56 >= buffer % 64) as usize * (56 - buffer % 64) 
                + (56 < buffer % 64) as usize * (120 - buffer % 64);
  data.resize(data_len + pad_len, 0);
}