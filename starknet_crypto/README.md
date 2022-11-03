# `starknet_crypto`

A crate implementing Starknet field elements and the hash algorithm.

## Features

- Conversion of field elements to/from various binary representations
- [Pedersen hash](https://docs.starknet.io/documentation/develop/Hashing/hash-functions/#definition) calculation
- [Array hashing](https://docs.starknet.io/documentation/develop/Hashing/hash-functions/#array_hashing)
- Serde serialization (with the `serde` feature)

## Disclaimer

_The implementation is NOT constant time._ Do _not_ use this implementation to build digital signatures.
