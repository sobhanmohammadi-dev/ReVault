use clap::Parser;

use Ruvault::cli::{
    Cli,
    commands::{Commands, start::Start},
};

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => {
            Start::execute()?;
        }
    }

    Ok(())
}