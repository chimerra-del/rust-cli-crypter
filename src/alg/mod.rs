pub mod aes;
pub mod block_cipher;
pub mod camelia;
pub mod chacha20;
pub mod madryga;
pub mod rc4;
pub mod rc5;
pub mod salsa20;
pub mod viginere;
pub mod xorshift;
pub mod xtea;

pub use rc4::{rc4_init, rc4_crypt};
pub use xtea::xtea_encrypt;
pub use xorshift::process_file;
pub use madryga::madryga_encrypt;
pub use viginere::viginere_encrypt; 
pub use salsa20::Salsa20;
pub use salsa20::salsa20_encrypt;
pub use rc5::rc5_encrypt;
pub use aes::cipher;

pub use block_cipher::BlockCipher;
