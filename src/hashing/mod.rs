pub mod murmurhash3;
pub mod fnv1a;
pub mod djb2;

pub use murmurhash3::murmur;
pub use fnv1a::fnv1a_hash;
pub use djb2::djb2_hash;