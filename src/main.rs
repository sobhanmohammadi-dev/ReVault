use clap::Parser;

use Ruvault::cli::{
    Cli,
    commands::{
        network::{Grant, Join, Revoke, Serve, Whoami},
        vault::{Add, Create, Delete, List, Update, Verify},
        start::Start,
        Commands,
    },
};

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Start => {
            Start::execute()?;
        }
        Commands::Create { path, name, description, capacity, password } => {
            Create::execute(path, name, description, capacity, password)?;
        }
        Commands::List { vault, password } => {
            List::execute(vault, password)?;
        }
        Commands::Verify { vault, password } => {
            Verify::execute(vault, password)?;
        }
        Commands::Add { vault, password, source, name } => {
            Add::execute(vault, password, source, name)?;
        }
        Commands::Update { vault, password, source, name } => {
            Update::execute(vault, password, source, name)?;
        }
        Commands::Delete { vault, password, name } => {
            Delete::execute(vault, password, name)?;
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
