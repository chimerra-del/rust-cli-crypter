use std::env;
use std::fs;
use std::path::Path;
use std::io::{self, Write};

mod alg;
mod rsp_parser;
mod passwd_hashing;
mod hashing;

/// Конфигурация для криптографических операций
#[derive(Debug, Clone)]
struct CryptoConfig {
    file_path: Option<String>,
    algorithm: Option<String>,
    action: Option<String>,
    key: Option<Vec<u8>>,
    hash_function: Option<String>,
    salt: Option<Vec<u8>>,
    info: Option<Vec<u8>>,
}

impl CryptoConfig {
    fn new() -> Self {
        CryptoConfig {
            file_path: None,
            algorithm: None,
            action: None,
            key: None,
            hash_function: None,
            salt: None,
            info: None,
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
        if args.len() > 6 {
            config.salt = Some(args[6].as_bytes().to_vec());
        }
        if args.len() > 7 {
            config.info = Some(args[7].as_bytes().to_vec());
        }

        config
    }

    /// Проверить и заполнить недостающие параметры
    fn validate_and_complete(&mut self) -> Result<(), String> {
        // Если указан алгоритм хеширования, то ключ и действие не нужны
        if self.hash_function.is_some() {
            return Ok(());
        }

        // Если HKDF, то не требуется действие и проверка файла
        if matches!(self.algorithm.as_ref().map(|a| a.as_str()), Some("hkdf")) {
            if self.key.is_none() {
                eprintln!("(!) Ключ (IKM) не указан, сгенерируем сами!");
                self.key = Some(generate_random_key(32));
                eprintln!("(✓) Сгенерирован случайный ключ длиной 32 байта");
            }
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
            eprintln!("(!) Seed не указан, генерируем случайный...");
            let generated = generate_random_seed();
            eprintln!("✓ Сгенерирован seed: {}", generated);
            generated
        })
}

/// Список функций вызовов для хеширования строк
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

/// Список функций вызовов для шифрования
/// Функция для шифрования файла RC4
fn rc4_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Инициализируем RC4
    let mut state = alg::rc4_init(key);
    // Шифруем
    alg::rc4_crypt(&mut state, &mut data);
    // Сохраняем в новый файл
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла XTEA
fn xtea_encrypt_file(file_path: &str, _key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(file_path)?;
    
    // Преобразуем данные в массив u32[2] (XTEA работает с 8 байтами)
    if data.len() < 8 {
        return Err("Данные должны быть минимум 8 байт для XTEA".into());
    }
    
    let mut block = [0u32; 2];
    block[0] = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    block[1] = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    
    // XTEA ключ - 4 u32
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
    
    // Преобразуем ключ в u64
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
fn vigenere_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let buffer = fs::read_to_string(file_path)?;
    let key_str = String::from_utf8_lossy(key);
    let output_path = format!("{}.enc", file_path);
    
    let processed_data = alg::viginere_encrypt(&buffer, &key_str, false);
    fs::write(&output_path, &processed_data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла Salsa20
fn salsa20_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = fs::read(file_path)?;
    let nonce = [0u8; 8];
    let key_array: &[u8; 32] = key.try_into().expect("Неверная длина ключа");
    let encrypted = alg::salsa20_encrypt(&mut data, key_array, &nonce);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла RC5
fn rc5_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read(file_path)?;
    
    // RC5 требует 3 аргумента: &[u8], u8 (rounds), и выходной буфер
    let rounds = 12u8;  // стандартное количество раундов
    let mut output = vec![0u8; data.len()];
    
    alg::rc5_encrypt(&data, rounds, &data, &mut output);
    
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &output)?;
    println!("✓ Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

/// Функция для шифрования файла AES
fn aes_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = fs::read(file_path)?;
    
    // AES требует ровно 16 байт для блока и ключа
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

/// ТУТ НАЧИНАЮТСЯ ТЕСТЫ(Tests) ДЛЯ ВСЕХ АЛГОРИТМОВ ЧЕРЕЗ RSP ФАЙЛЫ
fn aes_test_rsp(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let testing_str = fs::read_to_string(file_path)?;
    println!("Убедитесь, что тесты загружены в папку рядом с main.rs, у нас пока что проблемы, скачайте сами, извините.");
    rsp_parser::run_tests(&testing_str)?;
    println!("✓ Тесты запущены, передаём управление парсеру");
    Ok(())
}

/// Функция для HKDF операций
fn hkdf_derive(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let ikm = config
        .key
        .as_ref()
        .ok_or("IKM (ключевой материал) не указан")?;
    
    let salt = config.salt.as_ref().map(|s| s.as_slice()).unwrap_or(&[]);
    let info = config.info.as_ref().map(|i| i.as_slice()).unwrap_or(&[]);
    
    // Длина вывода - 32 байта по умолчанию (для SHA-256)
    let output_length = 32;  
    // Extract этап
    let prk = passwd_hashing::hkdf_extract(salt, ikm);  
    // Expand этап
    let okm = passwd_hashing::hkdf_expand(&prk, info, output_length);
    let output_path = "hkdf_output.bin";
    fs::write(output_path, &okm)?;
    println!("✓ Результат сохранён в: {}", output_path);
    
    Ok(())
}

/// Обработать хеширование на основе конфигурации
fn handle_hashing(config: &CryptoConfig) -> Result<(), Box<dyn std::error::Error>> {
    let hash_fn = config
        .hash_function
        .as_ref()
        .ok_or("Хеш-функция не указана")?;

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
    let algorithm = config
        .algorithm
        .as_ref()
        .ok_or("Алгоритм не указан")?;

    match algorithm.as_str() {
        "hkdf" => {
            hkdf_derive(config)?;
        }
        "rc4" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            rc4_encrypt_file(file_path, key)?;
        }
        "xtea" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            xtea_encrypt_file(file_path, key)?;
        }
        "xorshift" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            xorshift_encrypt_file(file_path, &[])?;
        }
        "madryga" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            madryga_encrypt_file(file_path, key)?;
        }
        "vigenere" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            vigenere_encrypt_file(file_path, key)?;
        }
        "salsa20" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            salsa20_encrypt_file(file_path, key)?;
        }
        "rc5" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            rc5_encrypt_file(file_path, key)?;
        }
        "aes" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            let key = config.key.as_ref().ok_or("Ключ не указан")?;
            aes_encrypt_file(file_path, key)?;
        }
        "aes-test" => {
            let file_path = config.file_path.as_ref().ok_or("Путь к файлу не указан")?;
            aes_test_rsp(file_path)?;
        }
        _ => {
            eprintln!("(!) Неизвестный алгоритм: {}", algorithm);
            return Err(format!("Неизвестный алгоритм: {}", algorithm).into());
        }
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut config = CryptoConfig::from_args(&args);
    
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
        // Операция шифрования/дериватиции
        if let Err(e) = handle_encryption(&config) {
            eprintln!("(!) Ошибка операции: {}", e);
        }
    }
}
