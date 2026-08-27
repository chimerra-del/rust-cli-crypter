use std::env;
use std::fs;
use std::path::Path;

mod rc4;
mod madryga;
mod lucifer;
mod salsa20;
mod chacha20;
mod xtea;
mod rc5;
mod viginere;
mod xorshift;

use rc4::{rc4_init, rc4_crypt};

// Полный список возможных(Будущих) аргументов
/* 
–- alg
-- aead
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

    let password = match args.get(4) {
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
            if let Err(e) = rc4_encrypt_file(&file_path, password.as_bytes()) {
                eprintln!("Ошибка шифрования: {}", e);
            }
        }
        _ => {
            eprintln!("Неизвестный алгоритм: {}", alg);
        }
    }
}

// Функция для шифрования файла
fn rc4_encrypt_file(file_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;    
    // Инициализируем RC4
    let mut state = rc4_init(password);
    // Шифруем
    rc4_crypt(&mut state, &mut data);
    // Сохраняем в новый файл
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn xtea_encrypt_file(file_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    xtea_encrypt(&mut state, &mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn xorshift_encrypt_file(file_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    process_file(&mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn madryga_encrypt_file(file_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Читаем файл
    let mut data = fs::read(file_path)?;
    // Шифруем
    madryga_encrypt(&mut data);
    let output_path = format!("{}.enc", file_path);
    fs::write(&output_path, &data)?;
    println!("Файл зашифрован и сохранён в: {}", output_path);
    Ok(())
}

fn viginere_encrypt_file(file_path: &str, password: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
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