//! Revault: a secure, single-file local vault with optional
//! peer-to-peer sharing. See `/README.md` for an overview and
//! `/docs/ARCHITECTURE_NETWORK.md` for the network/sharing design.
#![allow(non_snake_case)] // package name is `Ruvault`, used verbatim in `use Ruvault::...` throughout

pub mod cli;
pub mod core;
pub mod net;
pub mod tui;