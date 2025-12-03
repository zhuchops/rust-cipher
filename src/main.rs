use clap::Parser;

#[derive(Parser)]
struct Cli {
    pattern: String,
    path: std::path::PathBuf,
}

fn main() {
    let cli = Cli::parse();
    println!("pattern: {:?}, path: {:?}", cli.pattern, cli.path)
}
