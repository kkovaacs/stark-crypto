# `starknet_crypto`

Rust crate for Starknet crypto primitives.

Currently implements the finite field, the elliptic curve and hash algorithms.

## Features

- Conversion of field elements to/from various binary representations
- [Pedersen hash](https://docs.starknet.io/documentation/develop/Hashing/hash-functions/#definition) calculation
- [Array hashing](https://docs.starknet.io/documentation/develop/Hashing/hash-functions/#array_hashing)
- Serde serialization (with the `serde` feature)

## Disclaimer

_The implementation is NOT constant time._ Do _not_ use this implementation to build digital signatures.
