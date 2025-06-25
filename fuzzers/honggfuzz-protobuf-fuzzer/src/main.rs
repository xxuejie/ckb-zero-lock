use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Input mock tx file
    #[arg(long)]
    input: String,
}

fn main() {
    let cli = Cli::parse();

    let data = std::fs::read(&cli.input).expect("read input file!");
    let code = honggfuzz_protobuf_fuzzer::run(&data);
    println!("Exit code: {}", code);
    std::process::exit(code as i32);
}
