use std::fs::File;
use std::io::{BufRead, BufReader};
use std::collections::HashMap;

use crate::aes::AES;
use crate::block_cipher::BlockCipher;

pub struct RspParser {
    file_path: String,
}

#[derive(Debug, Clone)]
pub struct TestCase {
    pub count: usize,
    pub key: Vec<u8>,
    pub plaintext: Option<Vec<u8>>,
    pub ciphertext: Option<Vec<u8>>,
    pub mode: TestMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TestMode {
    Encrypt,
    Decrypt,
}

impl RspParser {
    pub fn new(file_path: &str) -> Self {
        RspParser {
            file_path: file_path.to_string(),
        }
    }

    pub fn parse(&self) -> Result<Vec<TestCase>, Box<dyn std::error::Error>> {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        
        let mut test_cases = Vec::new();
        let mut current_mode = TestMode::Encrypt;
        let mut current_test: HashMap<String, String> = HashMap::new();
        let mut test_count = 0;

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed == "[ENCRYPT]" {
                current_mode = TestMode::Encrypt;
                current_test.clear();
                continue;
            }

            if trimmed == "[DECRYPT]" {
                current_mode = TestMode::Decrypt;
                current_test.clear();
                continue;
            }

            if let Some(eq_pos) = trimmed.find('=') {
                let key = trimmed[..eq_pos].trim().to_uppercase();
                let value = trimmed[eq_pos + 1..].trim().to_string();
                
                current_test.insert(key, value);
                if key == "CIPHERTEXT" || (key == "PLAINTEXT" && current_mode == TestMode::Decrypt) {
                    if let Some(test_case) = self.build_test_case(
                        &current_test,
                        current_mode.clone(),
                        test_count,
                    ) {
                        test_cases.push(test_case);
                        test_count += 1;
                        current_test.clear();
                    }
                }
            }
        }

        Ok(test_cases)
    }

    fn build_test_case(
        &self,
        data: &HashMap<String, String>,
        mode: TestMode,
        count: usize,
    ) -> Option<TestCase> {
        let key = data.get("KEY")?;
        let key_bytes = hex_to_bytes(key).ok()?;

        match mode {
            TestMode::Encrypt => {
                let plaintext = data.get("PLAINTEXT")?;
                let ciphertext = data.get("CIPHERTEXT")?;
                let plaintext_bytes = hex_to_bytes(plaintext).ok()?;
                let ciphertext_bytes = hex_to_bytes(ciphertext).ok()?;

                Some(TestCase {
                    count,
                    key: key_bytes,
                    plaintext: Some(plaintext_bytes),
                    ciphertext: Some(ciphertext_bytes),
                    mode,
                })
            }
            TestMode::Decrypt => {
                let ciphertext = data.get("CIPHERTEXT")?;
                let plaintext = data.get("PLAINTEXT")?;
                let ciphertext_bytes = hex_to_bytes(ciphertext).ok()?;
                let plaintext_bytes = hex_to_bytes(plaintext).ok()?;

                Some(TestCase {
                    count,
                    key: key_bytes,
                    plaintext: Some(plaintext_bytes),
                    ciphertext: Some(ciphertext_bytes),
                    mode,
                })
            }
        }
    }
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim().to_uppercase();
    
    if hex.len() % 2 != 0 {
        return Err(format!("Нечётная длина HEX строки: {}", hex));
    }

    let mut bytes = Vec::new();
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("Ошибка парсинга HEX байта '{}': {}", byte_str, e))?;
        bytes.push(byte);
    }

    Ok(bytes)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<String>()
}

pub fn run_tests(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parser = RspParser::new(file_path);
    let test_cases = parser.parse()?;

    println!("Загружено {} тестовых случаев", test_cases.len());
    println!("{}═══════════════════════════════════════", "═".repeat(50));

    let mut passed = 0;
    let mut failed = 0;

    for test_case in test_cases {
        match run_single_test(&test_case) {
            Ok(_) => {
                passed += 1;
                println!(
                    "✓ Тест #{}: {} - ПРОЙДЕН",
                    test_case.count,
                    if test_case.mode == TestMode::Encrypt {
                        "ENCRYPT"
                    } else {
                        "DECRYPT"
                    }
                );
            }
            Err(e) => {
                failed += 1;
                println!(
                    "✗ Тест #{}: {} - ОШИБКА",
                    test_case.count,
                    if test_case.mode == TestMode::Encrypt {
                        "ENCRYPT"
                    } else {
                        "DECRYPT"
                    }
                );
                println!("  └─ {}", e);
            }
        }
    }

    println!("{}═══════════════════════════════════════", "═".repeat(50));
    println!(
        "Результаты: {} пройдено, {} не пройдено",
        passed, failed
    );

    if failed > 0 {
        Err(format!("Не пройдено тестов: {}", failed).into())
    } else {
        Ok(())
    }
}

fn run_single_test(test_case: &TestCase) -> Result<(), String> {
    // Проверяем размер ключа (поддерживаем только AES-128)
    if test_case.key.len() != 16 {
        return Err(format!(
            "Неподдерживаемый размер ключа: {} байт (ожидается 16)",
            test_case.key.len()
        ));
    }

    // Преобразуем ключ в массив [u8; 16]
    let mut key_array = [0u8; 16];
    key_array.copy_from_slice(&test_case.key);

    let aes = AES::new(key_array);

    match test_case.mode {
        TestMode::Encrypt => {
            if let Some(ref plaintext) = test_case.plaintext {
                if plaintext.len() != 16 {
                    return Err(format!(
                        "Неподдерживаемый размер plaintext: {} байт (ожидается 16)",
                        plaintext.len()
                    ));
                }

                let result = aes.encrypt_block(plaintext);
                
                if let Some(ref expected_ciphertext) = test_case.ciphertext {
                    if result != *expected_ciphertext {
                        return Err(format!(
                            "Несоответствие CIPHERTEXT:\n    Получено:  {}\n    Ожидалось: {}",
                            bytes_to_hex(&result),
                            bytes_to_hex(expected_ciphertext)
                        ));
                    }
                }
            } else {
                return Err("Отсутствует PLAINTEXT в тестовом случае".to_string());
            }
        }

        TestMode::Decrypt => {
            if let Some(ref ciphertext) = test_case.ciphertext {
                if ciphertext.len() != 16 {
                    return Err(format!(
                        "Неподдерживаемый размер ciphertext: {} байт (ожидается 16)",
                        ciphertext.len()
                    ));
                }

                let result = aes.decrypt_block(ciphertext);
                
                if let Some(ref expected_plaintext) = test_case.plaintext {
                    if result != *expected_plaintext {
                        return Err(format!(
                            "Несоответствие PLAINTEXT:\n    Получено:  {}\n    Ожидалось: {}",
                            bytes_to_hex(&result),
                            bytes_to_hex(expected_plaintext)
                        ));
                    }
                }
            } else {
                return Err("Отсутствует CIPHERTEXT в тестовом случае".to_string());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_to_bytes() {
        let hex = "48656C6C6F"; // "Hello" в HEX
        let bytes = hex_to_bytes(hex).unwrap();
        assert_eq!(bytes, vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]);
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F];
        let hex = bytes_to_hex(&bytes);
        assert_eq!(hex, "48656C6C6F");
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        let hex = "48656C6C6F4"; // Нечётная длина
        assert!(hex_to_bytes(hex).is_err());
    }
}
