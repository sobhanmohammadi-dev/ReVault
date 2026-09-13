use clap::Parser;

use Ruvault::cli::{
    Cli,
    commands::{
        Commands,
        network::{Grant, Join, Revoke, Serve, Whoami},
        start::Start,
    },
};

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => {
            Start::execute()?;
        }
        Commands::Whoami { listen } => {
            Whoami::execute(listen)?;
        }
        Commands::Grant { vault, password, peer } => {
            Grant::execute(vault, password, peer)?;
        }
        Commands::Revoke { vault, password, peer } => {
            Revoke::execute(vault, password, peer)?;
        }
        Commands::Serve { vault, password, listen } => {
            Serve::execute(vault, password, listen)?;
        }
        Commands::Join { invite, out } => {
            Join::execute(invite, out)?;
        }
    }

    Ok(())
}
