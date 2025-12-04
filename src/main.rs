use std::{
    fmt::format,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit,
    aead::{AeadMut, OsRng},
    aes::cipher,
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
        encrypt_file(&args.path, password)?;
    } else {
        decrypt_file(&args.path, password.as_str())?;
    }
    Ok(())
}

fn derive_key(user_password: String, salt: String) -> [u8; 32] {
    let mut output_key = [0u8; 32];

    let argon2 = Argon2::default();

    argon2
        .hash_password_into(user_password.as_bytes(), salt.as_bytes(), &mut output_key)
        .expect("Failed to derive key");
    output_key
}

fn encrypt_file(path: &PathBuf, password: String) -> Result<(), anyhow::Error> {
    let salt = SaltString::generate(&mut OsRng);

    let key_bytes = derive_key(password, salt.to_string());
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
    todo!()
}
