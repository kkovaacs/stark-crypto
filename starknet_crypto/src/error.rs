use std::error::Error;

/// Error returned by [crate::Felt::from_be_bytes] indicating that
/// the maximum field value was exceeded.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct OverflowError;

impl Error for OverflowError {}

pub(crate) const OVERFLOW_MSG: &str = "The StarkHash maximum value was exceeded.";

impl std::fmt::Display for OverflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(OVERFLOW_MSG)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HexParseError {
    InvalidNibble(u8),
    InvalidLength { max: usize, actual: usize },
    Overflow,
}

impl Error for HexParseError {}

impl From<OverflowError> for HexParseError {
    fn from(_: OverflowError) -> Self {
        Self::Overflow
    }
}

impl std::fmt::Display for HexParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNibble(n) => f.write_fmt(format_args!("Invalid nibble found: 0x{:x}", *n)),
            Self::InvalidLength { max, actual } => {
                f.write_fmt(format_args!("More than {} digits found: {}", *max, *actual))
            }
            Self::Overflow => f.write_str(OVERFLOW_MSG),
        }
    }
}
