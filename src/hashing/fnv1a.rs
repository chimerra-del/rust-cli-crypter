// FNV-1a rust
// NOT SECURE

const FNV_OFFSET_BASIS: u32 = 0x811c9dc5;
const FNV_PRIME: u32 = 0x01000193;

pub fn fnv1a_hash(data: &[u8]) -> i32 {
  let mut hash = FNV_OFFSET_BASIS;
   for byte in data.iter() {
      hash ^= *byte as u32;
      hash = hash.wrapping_mul(FNV_PRIME);
   }
 hash.try_into().unwrap()
}