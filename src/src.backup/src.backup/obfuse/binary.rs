use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::hint;

const ROUNDS: usize = 16;
const JUNK_ENABLED: bool = true;
const EXTRA_JUNK: bool = true;
const DUMMY_ITERATIONS: usize = 1000;


fn get_junk_enabled() -> bool { JUNK_ENABLED }
fn get_extra_junk() -> bool { EXTRA_JUNK }
fn get_dummy_iterations() -> usize { DUMMY_ITERATIONS }

fn opaque_true() -> bool { true }
fn junk_guard() -> bool { true }

fn get_opaque_seed() -> u64 { 0xdeadbeef_cafebabe_u64 }

fn get_noise_matrix() -> Vec<Vec<u64>> {
    vec![
        vec![0x1234567890abcdef, 0xfedcba0987654321, 0xaaaaaaaaaaaaaaaa],
        vec![0xbbbbbbbbbbbbbbbb, 0xcccccccccccccccc, 0xdddddddddddddddd],
        vec![0xeeeeeeeeeeeeeeee, 0x1111111111111111, 0x2222222222222222],
    ]
}

fn get_twiddle_table() -> Vec<u64> {
    vec![
        0x9e3779b97f4a7c15, 0xbf58476d1ce4e5b9, 0x94d049bb133111eb,
        0x85ebca6b4cb4a405, 0xc2b2ae3d27d4eb4d, 0x27d4eb2d165667c3,
        0x3c6ef372fe94f82b, 0x52dce729e5a88e8d, 0x6f0a8b6ae16a8da3,
    ]
}

fn sbox_enc(x: u8) -> u8 {
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5f, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xd7, 0x4b, 0x55, 0xcf, 0x34, 0xc5, 0x84,
        0xcb, 0x2f, 0xce, 0x60, 0x9b, 0xb3, 0x44, 0x2c, 0xc2, 0x23, 0xc3, 0x18, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    ][x as usize]
}

fn _decoy_cipher_round(x: u64) -> u64 {
    x.wrapping_mul(0xdeadbeef_cafebabe_u64).rotate_left(17)
}

fn junk_cfg_dispatcher(acc: u64) -> u64 {
    hint::black_box(acc)
}

// ============================================================================
// ОСНОВНОЙ КОД ОБФУСКАЦИИ
// ============================================================================

fn junk_code() {
    if !get_junk_enabled() { return; }
    if !opaque_true()  { return; }
    if !junk_guard()   { return; }
    let noise   = get_noise_matrix();
    let twiddle = get_twiddle_table();
    let tw_len  = twiddle.len();
    let mut acc: u64 = get_opaque_seed();
    
    for row in &noise {
        for &cell in row { 
            acc = acc.wrapping_add(cell).rotate_left(13) ^ cell; 
        }
    }
    
    if get_extra_junk() {
        for i in 0..get_dummy_iterations() {
            acc = acc.wrapping_add(i as u64).wrapping_mul(0xdeadbeef_cafebabe_u64);
        }
        let mut fake_block = [0u8; 16];
        for (i, b) in fake_block.iter_mut().enumerate() {
            *b = sbox_enc(hint::black_box(twiddle[i % tw_len] as u8));
        }
        hint::black_box(fake_block);
        hint::black_box(_decoy_cipher_round(hint::black_box(acc)));
    } else {
        for &tw in twiddle.iter() { 
            acc ^= tw.rotate_right((tw & 63) as u32); 
        }
    }
    hint::black_box(junk_cfg_dispatcher(acc));
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn splitmix64_next(state: &mut u64) -> u64 {
    *state = splitmix64(*state);
    *state
}

fn fnv1a_stream_xor(data: &mut [u8], key: &[u8; 32]) {
    let mut counter = 0u64;
    for chunk in data.chunks_mut(8) {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(key);
        input.extend_from_slice(&counter.to_le_bytes());
        
        let mut hash: u64 = 14695981039346656037;
        for &b in &input { 
            hash ^= b as u64; 
            hash = hash.wrapping_mul(1099511628211); 
        }
        
        let keystream = hash.to_le_bytes();
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) { 
            *d ^= k; 
        }
        counter = counter.wrapping_add(1);
    }
}

fn splitmix64_stream_xor(data: &mut [u8], key: &[u8; 32]) {
    let mut state = u64::from_le_bytes(key[0..8].try_into().unwrap());
    for chunk in data.chunks_mut(8) {
        let rand = splitmix64_next(&mut state).to_le_bytes();
        for (d, r) in chunk.iter_mut().zip(rand.iter()) { 
            *d ^= r; 
        }
    }
}

fn feistel_round_function(x: u64, round_key: u64) -> u64 {
    let mixed = x.wrapping_add(round_key);
    let mut h: u64 = 14695981039346656037;
    for &b in &mixed.to_le_bytes() { 
        h ^= b as u64; 
        h = h.wrapping_mul(1099511628211); 
    }
    splitmix64(mixed) ^ h
}

fn generate_feistel_round_keys(key: &[u8; 32]) -> Vec<u64> {
    let mut state = u64::from_le_bytes(key[0..8].try_into().unwrap());
    (0..ROUNDS).map(|_| splitmix64_next(&mut state)).collect()
}

fn feistel_encrypt(data: &mut [u8], round_keys: &[u64]) {
    assert!(data.len() % 16 == 0, "Data length must be multiple of 16");
    for block in data.chunks_exact_mut(16) {
        let mut left  = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let mut right = u64::from_le_bytes(block[8..16].try_into().unwrap());
        
        for i in 0..ROUNDS {
            let f_out     = feistel_round_function(right, round_keys[i]);
            let new_left  = right;
            let new_right = left ^ f_out;
            left  = new_left;
            right = new_right;
        }
        
        block[0..8].copy_from_slice(&left.to_le_bytes());
        block[8..16].copy_from_slice(&right.to_le_bytes());
    }
}

fn pad_to_multiple(data: &mut Vec<u8>, multiple: usize) {
    let remainder = data.len() % multiple;
    if remainder != 0 {
        let padding_needed = multiple - remainder;
        data.resize(data.len() + padding_needed, 0u8);
    }
}

#[derive(Debug)]
pub enum ObfuscationMethod {
    Feistel,
    FnvStream,
    SplitmixStream,
    Combined,
}

#[derive(Debug)]
pub struct ObfuscatorConfig {
    pub method: ObfuscationMethod,
    pub key: [u8; 32],
    pub add_junk_code: bool,
}

impl Default for ObfuscatorConfig {
    fn default() -> Self {
        Self {
            method: ObfuscationMethod::Combined,
            key: [0x42; 32], // Стандартный ключ
            add_junk_code: true,
        }
    }
}

pub struct BinaryObfuscator {
    config: ObfuscatorConfig,
}

impl BinaryObfuscator {
    pub fn new(config: ObfuscatorConfig) -> Self {
        Self { config }
    }

    pub fn obfuscate_file<P: AsRef<Path>>(&self, input_path: P, output_path: P) -> io::Result<()> {
        let mut data = fs::read(&input_path)?;
        self.obfuscate_buffer(&mut data);
        fs::write(&output_path, &data)?;
        
        Ok(())
    }

    pub fn obfuscate_buffer(&self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        if self.config.add_junk_code {
            junk_code();
        }

        match self.config.method {
            ObfuscationMethod::Feistel => {
                self.apply_feistel(data);
            }
            ObfuscationMethod::FnvStream => {
                fnv1a_stream_xor(data, &self.config.key);
            }
            ObfuscationMethod::SplitmixStream => {
                splitmix64_stream_xor(data, &self.config.key);
            }
            ObfuscationMethod::Combined => {
                splitmix64_stream_xor(data, &self.config.key);
                self.apply_feistel(data);
                fnv1a_stream_xor(data, &self.config.key);
            }
        }
    }

    fn apply_feistel(&self, data: &mut [u8]) {
        let mut temp = data.to_vec();
        pad_to_multiple(&mut temp, 16);

        let round_keys = generate_feistel_round_keys(&self.config.key);
        feistel_encrypt(&mut temp, &round_keys);
        data.copy_from_slice(&temp[..data.len()]);
    }
}

pub fn obfuscate_file_simple<P: AsRef<Path>>(input: P, output: P) -> io::Result<()> {
    let config = ObfuscatorConfig::default();
    let obfuscator = BinaryObfuscator::new(config);
    obfuscator.obfuscate_file(input, output)
}

pub fn obfuscate_with_key<P: AsRef<Path>>(input: P, output: P, key: [u8; 32]) -> io::Result<()> {
    let mut config = ObfuscatorConfig::default();
    config.key = key;
    let obfuscator = BinaryObfuscator::new(config);
    obfuscator.obfuscate_file(input, output)
}