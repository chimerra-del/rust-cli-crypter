// DJB2 rust
// NOT SECURE

fn djb2_hash(data: &[u8]) {
  let mut hash: u32 = 5381;
    for byte in data.iter() { 
       hash.wrapping_shl(5); // Сдвинул на 5 бит влево
       hash.wrapping_add(hash).wrapping_add(*byte as u32);
    }
  hash
}