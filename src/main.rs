use std::env;
use std::fs;
use std::path::Path;

mod alg;
mod rsp_parser;

use rsp_parser::run_tests;
use rc4::{rc4_init, rc4_crypt};

// Полный список возможных(Будущих) аргументов
/* 
–- alg
-- mode
-- file_path
-- passwd_hash
-- key
-- obfuse
-- packer
-- crypter
*/

fn main() {
    let args: Vec<String> = env::args().collect();

    // Парсим аргументы
    let file_path = match args.get(1) {
        Some(arg) => arg.clone(),
        None => {
            eprintln!("Ошибка: не указан путь к файлу");
            return;
        }
    };

    let alg = match args.get(2) {
        Some(arg) => arg.clone(),
        None => {
            eprintln!("Ошибка: не указан алгоритм");
            return;
        }
    };

    let encrypt = match args.get(3) {
        Some(arg) => arg.clone(),
        None => {
            eprintln!("Ошибка: не указано действие (encrypt/decrypt)");
            return;
        }
    };

    let key = match args.get(4) {
        Some(arg) => arg.clone(),
        None => {
            eprintln!("Ошибка: не указан пароль");
            return;
        }
    };

    // Проверяем, существует ли файл
    if !Path::new(&file_path).exists() {
        eprintln!("Ошибка: файл '{}' не найден", file_path);
        return;
    }

    // Выбираем алгоритм
    match alg.as_str() {
        "rc4" => {
            if let Err(e) = rc4_encrypt_file(&file_path, key.as_bytes()) {
                eprintln!("Ошибка шифрования: {}", e);
            }
        }
         "xtea" => {
           if let Err(e) = xtea_encrypt_file(&file_path, key.as_bytes()) {
             eprintln!("Ошибка шифрования: {}", e);
           }
         }
        "xorshift" => {
          if let Err(e) = xorshift_encrypt_file(&file_path, key.as_bytes()) {
            eprintln!("Ошибка шифрования: {}", e);
          }
        }
        "madryga" => {
          if let Err(e) = madryga_encrypt_file(&file_path, key.as_bytes()) {
            eprintln!("Ошибка шифрования: {}", e);
          }
        }
        "viginere" => {
          if let Err(e) = viginere_encrypt_file(&file_path, key.as_bytes()) {
            eprintln!("Ошибка шифрования: {}", e);
          }
        }
        "salsa20" => {
          if let Err(e) = salsa20_encrypt_file(&file_path, key.as_bytes()) {
            eprintln!("Ошибка шифрования: {}", e);
          }
        }
        "rc5" => {
          if let Err(e) = rc5_encrypt_file(&file_path, key.as_bytes()) {
            eprintln!("Ошибка шифрования: {}", e);
          }
        }
       "aes-test" => {
         if let Err(e) = aes_test_rsp(&file_path) {
           eprintln!("Ошибка запуска теста AES-128: {}", e);
         }
       }
        _ => {
            eprintln!("Неизвестный алгоритм: {}", alg);
        }
    }
}
//! Список функций вызовов для шифрования
// Функция для шифрования файла
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
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn xtea_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    xtea_encrypt(&mut state, &mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn xorshift_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    process_file(&mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn madryga_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    madryga_encrypt(&mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

//? Возможны ошибки в реализации
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
}

fn salsa20_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Инициализируем
    let mut cipher = Salsa20::new(&key, &nonce);
    cipher.process(&mut data);
    let output_path = format!("{}.enc", file_path);
    std::fs::write(&output_path, &data)?;
    Ok(())
}

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
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn aes_encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let plaintext = fs::read(file_path)?;
    // Шифруем
    let ciphertext = aes::cipher(plaintext, key);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &encrypted)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
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
fn aes_test_rsp(&file_path) -> Result<(), Box<dyn std::error::Error>> {
   // Читаем путь к тестовому файлу
   let testing = fs::read(file_path)?;
   println!("Убедитесь, что тесты загружены в папку рядом с main.rs, у нас пока что проблемы, скачайте сами, извините.")
   // Запускаем тест
   rsp_parser::run_tests(testing)?;
   println!("Тесты запущены, передаём управление парсеру");
}