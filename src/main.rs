use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
    aead::{AeadMut, OsRng},
};
use argon2::{Argon2, password_hash::SaltString};
use clap::{ArgGroup, Parser, command};

#[derive(Debug, Parser)]
#[command(author = "zhuchops", version = "0.1", about = "simple cli to en\\decrypt files.", long_about = None)]
#[command(group(
    ArgGroup::new("mode")
    .required(true)
    .args(["encrypt", "decrypt"])
))]
struct Cli {
    #[arg(short, long)]
    encrypt: bool,

    #[arg(short, long)]
    decrypt: bool,

    #[arg(name = "PATH_TO_FILE")]
    path: PathBuf,
}

fn main() -> Result<(), anyhow::Error> {
    let args = Cli::parse();

    let password = rpassword::prompt_password("Enter password: ")?;

    if args.encrypt {
        encrypt_file(&args.path, password.as_str())?;
    } else {
        decrypt_file(&args.path, password.as_str())?;
    }
    Ok(())
}

fn derive_key(user_password: &str, salt: &str) -> [u8; 32] {
    let mut output_key = [0u8; 32];

    let argon2 = Argon2::default();

    argon2
        .hash_password_into(user_password.as_bytes(), salt.as_bytes(), &mut output_key)
        .expect("Failed to derive key");
    output_key
}

fn encrypt_file(path: &PathBuf, password: &str) -> Result<(), anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let key_bytes = derive_key(password, salt.as_str());
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);

    let mut cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = fs::read(path).expect("File not found");

    let cipher_text = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

    let output_name = format!("{}.enc", path.file_name().unwrap().to_str().unwrap());
    println!("{:?}", path);
    println!("{}", output_name);
    let mut file = File::create(&output_name).unwrap();

    let salt_bytes = salt.as_str().as_bytes();
    file.write_all(&[salt_bytes.len() as u8]).unwrap();
    file.write_all(salt_bytes).unwrap();

    file.write_all(&nonce).unwrap();
    file.write_all(&cipher_text).unwrap();
    Ok(())
}
fn decrypt_file(path: &Path, password: &str) -> Result<(), anyhow::Error> {
    let file = fs::read(path).expect("cannot read file");

    let salt_len = file[0] as usize;

    let salt_bytes = &file[1..1 + salt_len];
    let salt_str = std::str::from_utf8(salt_bytes).expect("Invalid salt encoding");

    let key_bytes = derive_key(password, salt_str);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    let nonce_start = 1 + salt_len;
    let nonce_end = nonce_start + 12;
    let nonce_bytes = &file[nonce_start..nonce_end];
    let nonce = Nonce::from_slice(nonce_bytes);

    let ciphertext = &file[nonce_end..];

    let mut cipher = Aes256Gcm::new(key);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .expect("Wrong password or corrupted file");

    let input_name = path.file_name().unwrap().to_str().unwrap();
    let input_name_list = input_name.split('.').collect::<Vec<&str>>();
    let output_name_list = &input_name_list[0..input_name_list.len() - 1];
    let output_name = output_name_list.join(".");

    let mut file = File::create(&output_name).expect("Error creating file");
    file.write_all(&plaintext).expect("Error writing to file");

    // println!("Decrypted file:\n{}", String::from_utf8_lossy(&plaintext));

    Ok(())
}
