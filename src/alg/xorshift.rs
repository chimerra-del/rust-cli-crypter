use std::fs::File;
use std::io::{self, Read, Write};

pub fn process_file(input_path: &str, output_path: &str, seed: u32) -> io::Result<()> {
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;

    let mut rng = Xorshift32::new(seed);
    for byte in &mut buffer {
        *byte ^= rng.next_byte();
    }

    output_file.write_all(&buffer)?;
    Ok(())
}

struct Xorshift32 {
    state: u32,
}

impl Xorshift32 {
    fn new(seed: u32) -> Self {
        let initial = if seed == 0 { 1 } else { seed };
        Self { state: initial }
    }

    fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    fn next_byte(&mut self) -> u8 {
        (self.next_u32() & 0xFF) as u8
    }
}