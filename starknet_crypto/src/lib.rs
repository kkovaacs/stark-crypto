//! Rust crate for Starknet crypto primitives.
//!
//! Currently implements the finite field, the elliptic curve (via `starknet_curve`) and hash algorithms.
//!
//! DISCLAIMER: the implementation is _not_ constant time. Do _not_ use this crate to construct digital
//! signatures.

#![deny(rust_2018_idioms)]

mod chain;
mod error;
mod felt;
mod hash;
#[cfg(feature = "serde")]
mod serde;

pub use chain::HashChain;
pub use error::{HexParseError, OverflowError};
pub use felt::Felt;
pub use hash::stark_hash;
