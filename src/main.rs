use std::path::{Path, PathBuf};

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

fn derive_key(user_password: String) {
    todo!()
}

fn encrypt_file(path: &PathBuf, password: &str) -> Result<(), anyhow::Error> {
    todo!()
}
fn decrypt_file(path: &Path, password: &str) -> Result<(), anyhow::Error> {
    todo!()
}
