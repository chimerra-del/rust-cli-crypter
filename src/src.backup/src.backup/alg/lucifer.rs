// Теперь я собственность картеля
// Ниблы
const S0: [u8; 16] = [
    0x0C, 0x0F, 0x07, 0x09, 0x0E, 0x0D, 0x0C, 0x01,
    0x05, 0x0B, 0x03, 0x00, 0x08, 0x06, 0x04, 0x0A
];

const S1: [u8; 16] = [
    0x07, 0x02, 0x0E, 0x09, 0x03, 0x0B, 0x00, 0x04,
    0x0C, 0x0D, 0x01, 0x0A, 0x06, 0x0F, 0x08, 0x05
];

// Структура для хранения ключей раунда
#[derive(Debug, Clone)]
struct RoundKey {
    round: u32,
    subkey: [u8; 8],
    icb: u8,
}

// Из 128-битного ключа генерируются подключи для каждого раунда
fn key_shledule_lucifer() {
  let mut round_keys = Vec::new();
  value.rotate_left(shift)
  for r in 0..num_rounds {
        let subkey_int = self.key_register >> 64;
        let subkey_bytes = subkey_int.to_be_bytes();
        let icb_byte = ((self.key_register >> 56) & 0xFF) as u8;
        
        round_keys.push(RoundKey {
            round: r + 1,
            subkey: subkey_bytes,
            icb: icb_byte,
        });
        self.key_register = self.key_register.rotate_left(56);
    }
    
    round_keys
}