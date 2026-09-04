use std::fs;
use std::path::Path;
use std::io::{self, Write};
use clap::Parser;
use cipher_factory::CipherFactory;
use cipher_modes::{EcbMode, CbcMode, CtrMode};

mod cipher_implementations;
mod cipher_modes;
mod cipher_factory;
mod alg;
mod rsp_parser;
mod passwd_hashing;
mod hashing;

/// Конфигурация для криптографических операций
#[derive(Debug, Clone, Parser)]
#[command(name = "Crypto Tool")]
#[command(about = "Инструмент для криптографических операций", long_about = None)]
struct CryptoConfig {
    /// Путь к файлу
    #[arg(long, short = 'p')]
    path: Option<String>,

    /// Алгоритм шифрования (aes, rc4, chacha20 и т.д.)
    #[arg(long, short = 'a')]
    alg: Option<String>,

    /// Действие (encrypt/decrypt)
    #[arg(long, short = 'f')]
    func: Option<String>,

    /// Ключ шифрования (hex или текст)
    #[arg(long, short = 'k')]
    key: Option<String>,

    /// Хеш-функция (murmurhash3, fnv1a, djb2)
    #[arg(long)]
    hash: Option<String>,

    /// Salt для HKDF
    #[arg(long, short = 's')]
    salt: Option<String>,

    /// Info для HKDF
    #[arg(long, short = 'i')]
    info: Option<String>,

    /// Режим шифрования (ecb, cbc, ctr, gcm)
    #[arg(long, short = 'm')]
    mode: Option<String>,

    /// Инициализационный вектор (hex)
    #[arg(long)]
    iv: Option<String>,

    /// Nonce для потоковых шифров (hex)
    #[arg(long)]
    nonce: Option<String>,
}

impl CryptoConfig {
    /// Преобразовать строку (hex или текст) в байты
    fn string_to_bytes(s: &str) -> Vec<u8> {
        // Пытаемся распарсить как hex
        hex::decode(s).unwrap_or_else(|_| s.as_bytes().to_vec())
    }

    /// Получить ключ в виде байтов
    fn get_key(&self) -> Result<Vec<u8>, String> {
        self.key
            .as_ref()
            .map(|k| Self::string_to_bytes(k))
            .ok_or_else(|| "Ключ не указан".to_string())
    }

    /// Получить путь к файлу
    fn get_path(&self) -> Result<&str, String> {
        self.path
            .as_ref()
            .map(|p| p.as_str())
            .ok_or_else(|| "Путь к файлу не указан".to_string())
    }

    /// Получить алгоритм
    fn get_alg(&self) -> Result<&str, String> {
        self.alg
            .as_ref()
            .map(|a| a.as_str())
            .ok_or_else(|| "Алгоритм не указан".to_string())
    }

    /// Проверить и заполнить недостающие параметры
    fn validate_and_complete(&mut self) -> Result<(), String> {
        // Если указана хеш-функция, то ключ и действие не нужны
        if self.hash.is_some() {
            return Ok(());
        }

        // Если HKDF, то не требуется действие и проверка файла
        if matches!(self.alg.as_ref().map(|a| a.as_str()), Some("hkdf")) {
            if self.key.is_none() {
                eprintln!("(!) Ключ (IKM) не указан, сгенерируем сами!");
                self.key = Some(hex::encode(generate_random_key(32)));
                eprintln!("(✓) Сгенерирован случайный ключ длиной 32 байта");
            }
            return Ok(());
        }

        // Проверяем файл
        if let Some(ref path) = self.path {
            if !Path::new(path).exists() {
                return Err(format!("Ошибка: файл '{}' не найден", path));
            }
        } else {
            return Err("Ошибка: не указан путь к файлу (используй --path или -p)".to_string());
        }

        // Проверяем алгоритм
        if self.alg.is_none() {
            return Err("Ошибка: не указан алгоритм (используй --alg или -a)".to_string());
        }

        // Проверяем действие (если это не тестирование)
        if !matches!(self.alg.as_ref().map(|a| a.as_str()), Some("aes-test")) {
            if self.func.is_none() {
                return Err(
                    "Ошибка: не указано действие (используй --func encrypt/decrypt или -f)"
                        .to_string(),
                );
            }
        }

        // Генерируем ключ, если не указан
        if self.key.is_none() {
            eprintln!("(!) Ключ не указан, сгенерируем сами!");
            self.key = Some(hex::encode(generate_random_key(32)));
            eprintln!("(✓) Сгенерирован случайный ключ длиной 32 байта");
        }

        Ok(())
    }
}

/// Генерировать случайный ключ через getrandom (syscall)
fn generate_random_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    getrandom::getrandom(&mut key).expect("Ошибка при генерации случайного ключа");
    key
}

/// Генерировать случайный seed для хеширования
fn generate_random_seed() -> u32 {
    let mut seed_bytes = [0u8; 4];
    getrandom::getrandom(&mut seed_bytes).expect("Ошибка при генерации seed'а");
    u32::from_le_bytes(seed_bytes)
}

/// Получить seed из пользователя или сгенерировать
fn get_or_generate_seed() -> u32 {
    println!("Введите seed для хеширования (или нажмите Enter для генерации): ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Ошибка при чтении ввода");

    input
        .trim()
        .parse::<u32>()
        .unwrap_or_else(|_| {
            eprintln!("(!) Seed не указан, генерируем случайный...");
            let generated = generate_random_seed();
            eprintln!("✓ Сгенерирован seed: {}", generated);
            generated
        })
}

/// Функция для хеширования строки через MurmurHash3
fn murmurhash3_hashing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let seed = get_or_generate_seed();
    let hash_str = hashing::murmur(seed, data);
    println!("Хеш вашей строки: {}", hash_str);
    Ok(())
}

fn fnv1a_hashing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let hash_str = hashing::fnv1a_hash(data);
    println!("Хеш вашей строки: {}", hash_str);
    Ok(())
}

fn djb2_hashing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let hash_str = hashing::djb2_hash(data);
    println!("Хеш вашей строки: {}", hash_str);
    Ok(())
}

/// Функция для шифрования файла RC4
fn rc4_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = fs::read(file_path)?;
    let mut state = alg::rc4_init(key);
    alg::rc4_crypt(&mut state, &mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла XTEA
fn xtea_encrypt_file(file_path: &str, _key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(file_path)?;

    if data.len() < 8 {
        return Err("Данные должны быть минимум 8 байт для XTEA".into());
    }

    let mut block = [0u32; 2];
    block[0] = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    block[1] = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    let key = [0u32; 4];

    alg::xtea_encrypt(&mut block, &key);

    let mut encrypted = Vec::new();
    encrypted.extend_from_slice(&block[0].to_le_bytes());
    encrypted.extend_from_slice(&block[1].to_le_bytes());

    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &encrypted)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла XORShift
fn xorshift_encrypt_file(file_path: &str, _key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let input_path = file_path;
    let output_path = format!("{}.enc", file_path);
    let seed = generate_random_seed();

    alg::process_file(input_path, &output_path, seed)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла Madryga
fn madryga_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = fs::read(file_path)?;

    let key_u64 = if key.len() >= 8 {
        u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]])
    } else {
        0u64
    };

    alg::madryga_encrypt(&mut data, key_u64);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла Vigenere
fn viginere_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let buffer = fs::read(file_path)?;  // Читаем как бинарные данные
    let output_path = format!("{}.enc", file_path);

    let processed_data = viginere_encrypt_bytes(&buffer, key, false);
    fs::write(&output_path, &processed_data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

// Вспомогательная функция
pub fn viginere_encrypt_bytes(data: &[u8], key: &[u8], decrypt: bool) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }

    data.iter()
        .enumerate()
        .map(|(i, &byte)| {
            let key_byte = key[i % key.len()];
            
            if decrypt {
                byte.wrapping_sub(key_byte)
            } else {
                byte.wrapping_add(key_byte)
            }
        })
        .collect()
}

/// Функция для шифрования файла Salsa20
fn salsa20_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = fs::read(file_path)?;
    let nonce = [0u8; 8];
    let key_array: &[u8; 32] = key.try_into().expect("Неверная длина ключа");
    let _encrypted = alg::salsa20_encrypt(&mut data, key_array, &nonce);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла Camellia
fn camellia_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(file_path)?;
    if data.len() < 16 {
        return Err("Данные должны быть минимум 16 байт для Camellia".into());
    }
    if key.len() < 32 {
        return Err("Ключ должен быть минимум 32 байт для Camellia-256".into());
    }

    let key_array: [u8; 32] = key[0..32].try_into()
        .map_err(|_| "Неверная длина ключа для Camellia")?;
    let camellia_key = alg::key_schedule(&key_array);
    let mut output = Vec::new();
    for chunk in data.chunks_exact(16) {
        let block: [u8; 16] = chunk.try_into()?;
        let encrypted = alg::camelia_encrypt(&block, &camellia_key);
        output.extend_from_slice(&encrypted);
    }
    let remainder = data.len() % 16;
    if remainder > 0 {
        let start = data.len() - remainder;
        let mut last_block = [0u8; 16];
        last_block[0..remainder].copy_from_slice(&data[start..]);
        let encrypted = alg::camelia_encrypt(&last_block, &camellia_key);
        output.extend_from_slice(&encrypted);
    }

    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &output)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла ChaCha20
fn chacha20_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(file_path)?;
    if key.len() < 32 {
        return Err("Ключ должен быть минимум 32 байт для ChaCha20".into());
    }
    let key_array: [u8; 32] = key[0..32].try_into()
        .map_err(|_| "Неверная длина ключа для ChaCha20")?;

    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;

    let encrypted = alg::chacha20_encrypt(&key_array, 0, &nonce, &data);
    let output_path = format!("{}.enc", file_path);
    let mut output = Vec::with_capacity(12 + encrypted.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);

    fs::write(&output_path, &output)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла RC5
fn rc5_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;    
    let data = fs::read(file_path)?;
    let rounds = 12u8;
    
    // Паддинг
    let pad_len = 8 - (data.len() % 8);
    let mut padded_data = data.clone();
    padded_data.extend(vec![pad_len as u8; if pad_len == 8 { 0 } else { pad_len }]); 
    // Выходной буфер такого же размера как входной с паддингом
    let mut output = vec![0u8; padded_data.len()];  
    // Шифруем каждый блок по 8 байт
    for (chunk_idx, chunk) in padded_data.chunks(8).enumerate() {
        let start = chunk_idx * 8;
        let end = start + 8;   
        // Подготавливаем блок для шифрования (всегда 8 байт)
        let mut block = [0u8; 8];
        block.copy_from_slice(chunk); // chunk всегда 8 байт из-за паддинга     
        // Шифруем блок
        let mut encrypted_block = [0u8; 8];
        alg::rc5_encrypt(key, rounds, &block, &mut encrypted_block);    
        // Записываем в выходной буфер
        output[start..end].copy_from_slice(&encrypted_block);
    }
    
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &output)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла AES
fn aes_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(file_path)?;

    if plaintext.len() < 16 {
        return Err("Данные должны быть минимум 16 байт для AES".into());
    }
    if key.len() < 16 {
        return Err("Ключ должен быть минимум 16 байт для AES".into());
    }

    let plaintext_block = <[u8; 16]>::try_from(&plaintext[0..16])?;
    let key_block = <[u8; 16]>::try_from(&key[0..16])?;

    let ciphertext = alg::cipher(&plaintext_block, &key_block);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &ciphertext)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Тесты для AES через RSP файлы
fn aes_test_rsp(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let testing_str = fs::read_to_string(file_path)?;
    println!("Убедитесь, что тесты загружены в папку рядом с main.rs, у нас пока что проблемы, скачайте сами, извините.");
    rsp_parser::run_tests(&testing_str)?;
    println!("✓ Тесты запущены, передаём управление парсеру");
    Ok(())
}

/// Функция для HKDF операций
fn hkdf_derive(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let ikm = config.key.as_ref().ok_or("IKM (ключевой материал) не указан")?;
    let ikm_bytes = CryptoConfig::string_to_bytes(ikm);

    let salt_bytes = config
        .salt
        .as_ref()
        .map(|s| CryptoConfig::string_to_bytes(s))
        .unwrap_or_default();

    let info_bytes = config
        .info
        .as_ref()
        .map(|i| CryptoConfig::string_to_bytes(i))
        .unwrap_or_default();

    let output_length = 32;
    let prk = passwd_hashing::hkdf_extract(&salt_bytes, &ikm_bytes);
    let okm = passwd_hashing::hkdf_expand(&prk, &info_bytes, output_length);
    let output_path = "hkdf_output.bin";
    fs::write(output_path, &okm)?;
    println!("✓ Результат сохранён в: {}", output_path);

    Ok(())
}

/// Обработать хеширование на основе конфигурации
fn handle_hashing(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let hash_fn = config
        .hash
        .as_ref()
        .ok_or("Хеш-функция не указана")?;

    let data = if let Some(ref file_path) = config.path {
        if Path::new(file_path).exists() {
            fs::read(file_path)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    match hash_fn.as_str() {
        "murmurhash3" => {
            murmurhash3_hashing(&data)?;
        }
        "fnv1a" => {
            fnv1a_hashing(&data)?;
        }
        "djb2" => {
            djb2_hashing(&data)?;
        }
        _ => {
            eprintln!("(!) Неизвестная хеш-функция: {}", hash_fn);
            return Err(format!("Неизвестная хеш-функция: {}", hash_fn).into());
        }
    }

    Ok(())
}

/// Обработать шифрование на основе конфигурации
fn handle_encryption(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let algorithm = config.get_alg()?;

    match algorithm {
        "hkdf" => {
            hkdf_derive(config)?;
        }
        "rc4" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            rc4_encrypt_file(file_path, &key)?;
        }
        "xtea" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            xtea_encrypt_file(file_path, &key)?;
        }
        "xorshift" => {
            let file_path = config.get_path()?;
            xorshift_encrypt_file(file_path, &[])?;
        }
        "madryga" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            madryga_encrypt_file(file_path, &key)?;
        }
        "vigenere" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            viginere_encrypt_file(file_path, &key)?;
        }
        "salsa20" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            salsa20_encrypt_file(file_path, &key)?;
        }
        "rc5" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            rc5_encrypt_file(file_path, &key)?;
        }
        "camelia" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            camellia_encrypt_file(file_path, &key)?;
        }
        "chacha20" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            chacha20_encrypt_file(file_path, &key)?;
        }
        "aes" => {
            let file_path = config.get_path()?;
            let key = config.get_key()?;
            aes_encrypt_file(file_path, &key)?;
        }
        "aes-test" => {
            let file_path = config.get_path()?;
            aes_test_rsp(file_path)?;
        }
        _ => {
            eprintln!("(!) Неизвестный алгоритм: {}", algorithm);
            return Err(format!("Неизвестный алгоритм: {}", algorithm).into());
        }
    }

    Ok(())
}

/// Обработать дешифрование на основе конфигурации
fn handle_decryption(_config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("(!) Дешифрование пока не реализовано");
    Err("Дешифрование пока не реализовано".into())
}

/// Режимы шифрования
fn encrypt_with_mode(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = config.get_path()?;
    let algorithm = config.get_alg()?;
    let mode = config.mode.as_ref().ok_or("Режим не указан")?;
    let key = config.get_key()?;

    let plaintext = fs::read(file_path)?;
    let cipher = CipherFactory::create_cipher(algorithm, &key)?;

    let ciphertext = match mode.to_lowercase().as_str() {
        "ecb" => EcbMode::encrypt(cipher.as_ref(), &plaintext)?,
        "cbc" => {
            let iv = config.iv.as_ref().ok_or("IV требуется для CBC")?;
            let iv_bytes = CryptoConfig::string_to_bytes(iv);
            CbcMode::new(iv_bytes)?.encrypt(cipher.as_ref(), &plaintext)?
        }
        "ctr" => {
            let nonce = config.nonce.as_ref().ok_or("Nonce требуется для CTR")?;
            let nonce_bytes = CryptoConfig::string_to_bytes(nonce);
            CtrMode::new(nonce_bytes)?.encrypt(cipher.as_ref(), &plaintext)?
        }
        _ => return Err(format!("Неизвестный режим: {}", mode).into()),
    };

    let output_path = format!("{}.{}.enc", file_path, mode.to_lowercase());
    fs::write(&output_path, &ciphertext)?;
    println!("✓ Файл зашифрован в: {}", output_path);
    Ok(())
}

fn decrypt_with_mode(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let file_path = config.get_path()?;
    let algorithm = config.get_alg()?;
    let mode = config.mode.as_ref().ok_or("Режим не указан")?;
    let key = config.get_key()?;

    let ciphertext = fs::read(file_path)?;
    let cipher = CipherFactory::create_cipher(algorithm, &key)?;

    let plaintext = match mode.to_lowercase().as_str() {
        "ecb" => EcbMode::decrypt(cipher.as_ref(), &ciphertext)?,
        "cbc" => {
            let iv = config.iv.as_ref().ok_or("IV требуется для CBC")?;
            let iv_bytes = CryptoConfig::string_to_bytes(iv);
            CbcMode::new(iv_bytes)?.decrypt(cipher.as_ref(), &ciphertext)?
        }
        "ctr" => {
            let nonce = config.nonce.as_ref().ok_or("Nonce требуется для CTR")?;
            let nonce_bytes = CryptoConfig::string_to_bytes(nonce);
            CtrMode::new(nonce_bytes)?.decrypt(cipher.as_ref(), &ciphertext)?
        }
        _ => return Err(format!("Неизвестный режим: {}", mode).into()),
    };

    let output_path = format!("{}.{}.dec", file_path, mode.to_lowercase());
    fs::write(&output_path, &plaintext)?;
    println!("✓ Файл расшифрован в: {}", output_path);
    Ok(())
}

fn main() {
    let mut config = CryptoConfig::parse();

    if let Err(e) = config.validate_and_complete() {
        eprintln!("(!) {}", e);
        std::process::exit(1);
    }
    let result: Result<(), Box<dyn std::error::Error>> = match () {
        _ if config.hash.is_some() => handle_hashing(&config),
        _ if config.mode.is_some() => {
            match config.func.as_deref() {
                Some("encrypt") => encrypt_with_mode(&config),
                Some("decrypt") => decrypt_with_mode(&config),
                _ => Err("Укажите --func encrypt или decrypt для режима блочного шифра".into()),
            }
        }
        _ => {
            match config.func.as_deref() {
                Some("encrypt") => handle_encryption(&config),
                Some("decrypt") => handle_decryption(&config),
                _ => handle_encryption(&config), // Запасной вариант (например, для hkdf)
            }
        }
    };

    if let Err(e) = result {
        eprintln!("❌ Ошибка выполнения: {}", e);
        std::process::exit(1);
    }
}