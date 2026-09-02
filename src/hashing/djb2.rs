// DJB2 rust
// NOT SECURE

pub fn djb2_hash(data: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    
    for byte in data.iter() {
        // hash * 33 = hash * (32 + 1) = (hash << 5) + hash
        hash = ((hash << 5).wrapping_add(hash)).wrapping_add(*byte as u32);
    }
    
    hash
}