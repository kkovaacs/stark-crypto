#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: [u8; 32]| {
    let constified = starknet_crypto::StarkHash::from_be_bytes(data);
    let orig = starknet_crypto::StarkHash::from_be_bytes_orig(data);
    assert_eq!(constified, orig);
});
