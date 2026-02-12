use std::path::Path;

use clap::Parser;

use etz::{cli::Cli, errors, run};

fn main() {
    let cli = Cli::parse();
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(err) => {
            eprintln!("error: failed to resolve current directory: {err}");
            std::process::exit(errors::EXIT_INTERNAL);
        }
    };

    match run(cli, Path::new(&cwd)) {
        Ok(()) => std::process::exit(errors::EXIT_OK),
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(errors::exit_code_for(&err));
        }
    }
}
