use std::env;
use std::fs;
use std::path::Path;
use std::io::{self, Write};

mod alg;
mod rsp_parser;

use rsp_parser::run_tests;
use rc4::{rc4_init, rc4_crypt};

/// Конфигурация для криптографических операций
#[derive(Debug, Clone)]
struct CryptoConfig {
    file_path: Option<String>,
    algorithm: Option<String>,
    action: Option<String>,
    key: Option<Vec<u8>>,
    hash_function: Option<String>,
}

impl CryptoConfig {
    fn new() -> Self {
        CryptoConfig {
            file_path: None,
            algorithm: None,
            action: None,
            key: None,
            hash_function: None,
        }
    }

    /// Заполнить конфигурацию из аргументов командной строки
    fn from_args(args: &[String]) -> Self {
        let mut config = CryptoConfig::new();

        if args.len() > 1 {
            config.file_path = Some(args[1].clone());
        }
        if args.len() > 2 {
            config.algorithm = Some(args[2].clone());
        }
        if args.len() > 3 {
            config.action = Some(args[3].clone());
        }
        if args.len() > 4 {
            config.key = Some(args[4].as_bytes().to_vec());
        }
        if args.len() > 5 {
            config.hash_function = Some(args[5].clone());
        }

        config
    }

    /// Проверить и заполнить недостающие параметры
    fn validate_and_complete(&mut self) -> Result<(), String> {
        // Если указан алгоритм хеширования, то ключ и действие не нужны
        if self.hash_function.is_some() {
            return Ok(());
        }

        // Проверяем файл
        if let Some(ref path) = self.file_path {
            if !Path::new(path).exists() {
                return Err(format!("Ошибка: файл '{}' не найден", path));
            }
        } else {
            return Err("Ошибка: не указан путь к файлу".to_string());
        }

        // Проверяем алгоритм
        if self.algorithm.is_none() {
            return Err("Ошибка: не указан алгоритм".to_string());
        }

        // Проверяем действие (если это не тестирование)
        if !matches!(self.algorithm.as_ref().map(|a| a.as_str()), Some("aes-test")) {
            if self.action.is_none() {
                return Err("Ошибка: не указано действие (encrypt/decrypt)".to_string());
            }
        }

        // Генерируем ключ, если не указан
        if self.key.is_none() {
            eprintln!("(!) Ключ не указан, сгенерируем сами!");
            self.key = Some(generate_random_key(32));
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
            eprintln!("⚠️ Seed не указан, генерируем случайный...");
            let generated = generate_random_seed();
            eprintln!("✓ Сгенерирован seed: {}", generated);
            generated
        })
}


//! Список функций вызовов для хеширования строк
/// Функция для хеширования строки через MurmurHash3
fn murmurhash3_hashing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let seed = get_or_generate_seed();
    let hash_str = murmur(seed, data);
    println!("Хеш вашей строки: {}", hash_str);
    Ok(())
}

fn fnv1a_hashing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
  let hash_str = fnv1a_hash(data);
    println!("Хеш вашей строки: {}", hash_str);
    Ok(())
}

fn djb2_hashing(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
  let hash_str = djb2_hash(data);
    println!("Хеш вашей строки: {}", hash_str);
    Ok(())
}




//! Список функций вызовов для шифрования
/// Функция для шифрования файла RC4
fn rc4_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Инициализируем RC4
    let mut state = rc4_init(key);
    // Шифруем
    rc4_crypt(&mut state, &mut data);
    // Сохраняем в новый файл
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла XTEA
fn xtea_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    xtea_encrypt(&mut state, &mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла XORShift
fn xorshift_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    process_file(&mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла Madryga
fn madryga_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    madryga_encrypt(&mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

//? Возможны ошибки в реализации
/// Функция для шифрования файла Vigenere
fn viginere_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::open(file_path)?;
    // Нужно передать файл в виде нужного формата, ведь это алфаитный шифр
    let mut buffer = Vec::new();
    data.read_to_end(&mut buffer)?;
    // Обработка данных
    let processed_data = vigenere_encrypt(&buffer, key, decrypt);
    // Запись результата в новый файл
    let mut output_file = File::create(output_path)?;
    output_file.write_all(&processed_data)?;
    Ok(())
}

/// Функция для шифрования файла Salsa20
fn salsa20_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Инициализируем
    let mut cipher = Salsa20::new(&key, &nonce);
    cipher.process(&mut data);
    let output_path = format!("{}.enc", file_path);
    std::fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла RC5
fn rc5_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let data = fs::read(file_path)?;
    let mut s = [0u8; 28];
    for (i, &byte) in key.iter().enumerate() {
        s[i % 28] ^= byte;
    }

    let rounds: u8 = 12;
    let mut encrypted = Vec::new();
    for chunk in data.chunks(8) {
        let mut padded = [0u8; 8];
        padded[..chunk.len()].copy_from_slice(chunk);

        let mut out = [0u8; 8];
        rc5::rc5_crypt_block(&s, rounds, &padded, &mut out);
        encrypted.extend_from_slice(&out);
    }

    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &encrypted)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла AES
fn aes_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let plaintext = fs::read(file_path)?;
    // Шифруем
    let ciphertext = aes::cipher(plaintext, key);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &encrypted)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/*
// ПРИМЕР СОЗДАНИЯ ПАР АЛГОРИТМ + РЕЖИМ
// Создаём AES с трейтом BlockCipher
    let cipher: Box<dyn BlockCipher> = Box::new(AES::new(key));

    // Используем с ECB
    let ciphertext = ecb::encrypt_ecb(cipher.as_ref(), plaintext);
    println!("Encrypted: {:?}", ciphertext);
*/

/// ТУТ НАЧИНАЮТСЯ ТЕСТЫ(Tests) ДЛЯ ВСЕХ АЛГОРИТМОВ ЧЕРЕЗ RSP ФАЙЛЫ
fn aes_test_rsp(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем путь к тестовому файлу
    let testing = fs::read(file_path)?;
    println!("Убедитесь, что тесты загружены в папку рядом с main.rs, у нас пока что проблемы, скачайте сами, извините.");
    // Запускаем тест
    rsp_parser::run_tests(testing)?;
    println!("✓ Тесты запущены, передаём управление парсеру");
    Ok(())
}


/// Обработать хеширование на основе конфигурации
fn handle_hashing(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let hash_fn = config
        .hash_function
        .as_ref()
        .ok_or("Хеш-функция не указана")?;

    // Если указан файл, читаем данные из файла, иначе используем пустые данные
    let data = if let Some(ref file_path) = config.file_path {
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
    let file_path = config
        .file_path
        .as_ref()
        .ok_or("Путь к файлу не указан")?;
    let algorithm = config
        .algorithm
        .as_ref()
        .ok_or("Алгоритм не указан")?;
    let key = config.key.as_ref().ok_or("Ключ не указан")?;

    match algorithm.as_str() {
        "rc4" => {
            rc4_encrypt_file(file_path, key)?;
        }
        "xtea" => {
            xtea_encrypt_file(file_path, key)?;
        }
        "xorshift" => {
            xorshift_encrypt_file(file_path, key)?;
        }
        "madryga" => {
            madryga_encrypt_file(file_path, key)?;
        }
        "viginere" => {
            viginere_encrypt_file(file_path, key)?;
        }
        "salsa20" => {
            salsa20_encrypt_file(file_path, key)?;
        }
        "rc5" => {
            rc5_encrypt_file(file_path, key)?;
        }
        "aes-test" => {
            aes_test_rsp(file_path)?;
        }
        _ => {
            eprintln!("(!) Неизвестный алгоритм: {}", algorithm);
            return Err(format!("Неизвестный алгоритм: {}", algorithm).into());
        }
    }

    Ok(())
}


// Блатной
fn main() {
    let args: Vec<String> = env::args().collect();
    // Парсим аргументы из командной строки
    let mut config = CryptoConfig::from_args(&args);
    // Проверяем и заполняем недостающие параметры
    if let Err(e) = config.validate_and_complete() {
        eprintln!("(!) {}", e);
        return;
    }

    // Определяем тип операции и выполняем
    if config.hash_function.is_some() {
        // Операция хеширования
        if let Err(e) = handle_hashing(&config) {
            eprintln!("(!) Ошибка хеширования: {}", e);
        }
    } else {
        // Операция шифрования
        if let Err(e) = handle_encryption(&config) {
            eprintln!("(!) Ошибка шифрования: {}", e);
        }
    }
}
