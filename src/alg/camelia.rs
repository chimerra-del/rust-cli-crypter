// My Fav Alg Camellia
// на основе RFC 3713

const SBOX: [u8; 256] = [
    60, 242, 25, 216, 58, 27, 73, 52, 207, 254, 213, 69, 21, 90, 66, 193,
    39, 162, 33, 153, 235, 1, 57, 28, 205, 23, 128, 149, 74, 146, 141, 246,
    117, 252, 80, 53, 229, 184, 192, 136, 113, 111, 181, 133, 253, 164, 188, 250,
    82, 110, 35, 233, 220, 125, 215, 208, 206, 203, 18, 138, 196, 104, 140, 226,
    101, 160, 156, 78, 30, 137, 17, 152, 62, 170, 56, 230, 225, 249, 157, 63,
    166, 143, 202, 32, 44, 98, 144, 198, 108, 183, 92, 147, 214, 190, 174, 243,
    211, 179, 175, 10, 42, 59, 139, 100, 49, 13, 131, 102, 50, 76, 109, 68,
    103, 34, 118, 47, 151, 4, 199, 248, 46, 16, 123, 81, 234, 70, 223, 201,
    155, 2, 64, 0, 107, 239, 12, 218, 40, 142, 19, 221, 29, 3, 178, 88,
    126, 119, 11, 209, 121, 150, 238, 97, 231, 182, 245, 77, 177, 94, 161, 26,
    89, 54, 244, 180, 176, 232, 22, 48, 91, 173, 24, 227, 112, 87, 169, 5,
    185, 135, 71, 224, 210, 191, 79, 129, 145, 251, 200, 130, 167, 186, 75, 115,
    163, 72, 105, 217, 116, 15, 236, 195, 61, 31, 241, 7, 114, 197, 45, 159,
    237, 222, 51, 168, 132, 165, 171, 219, 127, 6, 124, 204, 95, 122, 247, 187,
    106, 189, 158, 38, 14, 37, 20, 228, 86, 93, 9, 67, 43, 255, 148, 55,
    154, 240, 65, 84, 85, 8, 172, 99, 41, 194, 212, 120, 96, 36, 134, 83,
];

const MASK8: u8 = 0xff;
const MASK32: u32 = 0xffffffff;
const MASK64: u64 = 0xffffffffffffffff;

const SIGMA1: u64 = 0xA09E667F3BCC908B;
const SIGMA2: u64 = 0xB67AE8584CAA73B2;
const SIGMA3: u64 = 0xC6EF372FE94F82BE;
const SIGMA4: u64 = 0x54FF53A5F1D36F1C;
const SIGMA5: u64 = 0x10E527FADE682D1D;
const SIGMA6: u64 = 0xB05688C2B3E6C1FD;

pub struct CamelliaKey {
    kw: [u64; 4],    // Whitening ключи (kw1, kw2, kw3, kw4)
    k: [u64; 24],    // Раундовые ключи
    ke: [u64; 4],    // FL/FLINV ключи (ke1, ke2, ke3, ke4)
}

fn f(f_in: u64, ke: u64) -> u64 {
    let x = f_in ^ ke;
    let t1 = SBOX[((x >> 56) & MASK8 as u64) as usize] as u64;
    let t2 = SBOX[((x >> 48) & MASK8 as u64) as usize] as u64;
    let t3 = SBOX[((x >> 40) & MASK8 as u64) as usize] as u64;
    let t4 = SBOX[((x >> 32) & MASK8 as u64) as usize] as u64;
    let t5 = SBOX[((x >> 24) & MASK8 as u64) as usize] as u64;
    let t6 = SBOX[((x >> 16) & MASK8 as u64) as usize] as u64;
    let t7 = SBOX[((x >> 8) & MASK8 as u64) as usize] as u64;
    let t8 = SBOX[(x & MASK8 as u64) as usize] as u64;

    let y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    let y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    let y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    let y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    let y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    let y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    let y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    let y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;

    (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8
}

fn fl(fl_in: u64, ke: u64) -> u64 {
    let x1 = (fl_in >> 32) as u32;
    let x2 = (fl_in & MASK32 as u64) as u32;
    let k1 = (ke >> 32) as u32;
    let k2 = (ke & MASK32 as u64) as u32;

    let x2_new = x2 ^ ((x1 & k1).rotate_left(1));
    let x1_new = x1 ^ (x2_new | k2);

    ((x1_new as u64) << 32) | (x2_new as u64)
}

fn flinv(flinv_in: u64, ke: u64) -> u64 {
    let y1 = (flinv_in >> 32) as u32;
    let y2 = (flinv_in & MASK32 as u64) as u32;
    let k1 = (ke >> 32) as u32;
    let k2 = (ke & MASK32 as u64) as u32;

    let y1_new = y1 ^ (y2 | k2);
    let y2_new = y2 ^ ((y1_new & k1).rotate_left(1));

    ((y1_new as u64) << 32) | (y2_new as u64)
}

// ВАЙБКОД
fn key_schedule(key: &[u8; 32]) -> CamelliaKey {
    let kl = u64::from_be_bytes([
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
    ]);
    let kr = u64::from_be_bytes([
        key[8], key[9], key[10], key[11],
        key[12], key[13], key[14], key[15],
    ]);

    let mut d1 = kl;
    let mut d2 = kr;
    d2 ^= f(d1, SIGMA1);
    d1 ^= f(d2, SIGMA2);
    d1 ^= kl;
    d2 ^= kr;
    d2 ^= f(d1, SIGMA3);
    d1 ^= f(d2, SIGMA4);
    let ka = d1;
    let ka2 = d2;
    d1 = ka;
    d2 = ka2;
    d2 ^= f(d1, SIGMA5);
    d1 ^= f(d2, SIGMA6);
    let kb = d1;
    let kb2 = d2;
    let kw1 = kl;
    let kw2 = kr;
    let kw3 = ka;
    let kw4 = ka2;
    let ke1 = kb;
    let ke2 = kb2;
    let ke3 = ka;
    let ke4 = ka2;
    let mut k = [0u64; 24];
    let mut rot = 0;
    let key_sources = [kl, kr, ka, ka2, kb, kb2];
    let rotations = [
        0, 15, 30, 45, 60, 77, 94, 111, 128, 145, 162, 179,
        0, 15, 30, 45, 60, 77, 94, 111, 128, 145, 162, 179,
    ];

    for i in 0..24 {
        let source_idx = (i / 2) % 6;
        let source = key_sources[source_idx];
        let shift = rotations[i] % 64;
        k[i] = source.rotate_left(shift as u32);
    }

    CamelliaKey {
        kw: [kw1, kw2, kw3, kw4],
        k,
        ke: [ke1, ke2, ke3, ke4],
    }
}

//
pub fn camelia_encrypt(block: &[u8; 16], key: &CamelliaKey) -> [u8; 16] {
    let mut d1 = u64::from_be_bytes(block[0..8].try_into().unwrap());
    let mut d2 = u64::from_be_bytes(block[8..16].try_into().unwrap());
    
    d1 ^= key.kw[0];  // prewhitening
    d2 ^= key.kw[1];
    d2 ^= f(d1, key.k[0]);   // round 1
    d1 ^= f(d2, key.k[1]);   // round 2
    d2 ^= f(d1, key.k[2]);   // round 3
    d1 ^= f(d2, key.k[3]);   // round 4
    d2 ^= f(d1, key.k[4]);   // round 5
    d1 ^= f(d2, key.k[5]);   // round 6
    d1 = fl(d1, key.ke[0]);  // fl
    d2 = flinv(d2, key.ke[1]); // flinv
    d2 ^= f(d1, key.k[6]);   // round 7
    d1 ^= f(d2, key.k[7]);   // round 8
    d2 ^= f(d1, key.k[8]);   // round 9
    d1 ^= f(d2, key.k[9]);   // round 10
    d2 ^= f(d1, key.k[10]);  // round 11
    d1 ^= f(d2, key.k[11]);  // round 12
    d1 = fl(d1, key.ke[2]);  // fl
    d2 = flinv(d2, key.ke[3]); // flinv
    d2 ^= f(d1, key.k[12]);  // round 13
    d1 ^= f(d2, key.k[13]);  // round 14
    d2 ^= f(d1, key.k[14]);  // round 15
    d1 ^= f(d2, key.k[15]);  // round 16
    d2 ^= f(d1, key.k[16]);  // round 17
    d1 ^= f(d2, key.k[17]);  // round 18
    d1 = fl(d1, key.ke[2]);  // fl
    d2 = flinv(d2, key.ke[3]); // flinv
    d2 ^= f(d1, key.k[18]);  // round 19
    d1 ^= f(d2, key.k[19]);  // round 20
    d2 ^= f(d1, key.k[20]);  // round 21
    d1 ^= f(d2, key.k[21]);  // round 22
    d2 ^= f(d1, key.k[22]);  // round 23
    d1 ^= f(d2, key.k[23]);  // round 24
    d2 ^= key.kw[2];  // postwhitening
    d1 ^= key.kw[3];
    
    let mut result = [0u8; 16];
    result[0..8].copy_from_slice(&d1.to_be_bytes());
    result[8..16].copy_from_slice(&d2.to_be_bytes());
    
    result
}