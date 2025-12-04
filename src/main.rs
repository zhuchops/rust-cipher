use std::error::Error;

use clap::Parser;

#[derive(Parser)]
struct Cli {
    pattern: String,
    path: std::path::PathBuf,
}

#[derive(Debug)]
struct CustomError(String);

fn main() -> Result<(), CustomError> {
    let cli = Cli::parse();

    let content = std::fs::read_to_string(&cli.path)
        .map_err(|err| CustomError(format!("Error reading \'{:?}\': {}", cli.path, err)))?;
    println!("File content:\n{}", content);

    println!("Matches:");
    for line in content.lines() {
        if line.contains(&cli.pattern) {
            println!("{}", line)
        }
    }
    Ok(())
}
