pub mod commands;

use clap::Parser;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: commands::Commands,
}