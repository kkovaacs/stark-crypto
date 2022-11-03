#![deny(rust_2018_idioms)]

mod chain;
mod hash;
#[cfg(feature = "serde")]
mod serde;

pub use chain::HashChain;
pub use hash::{stark_hash, HexParseError, OverflowError, StarkHash};
