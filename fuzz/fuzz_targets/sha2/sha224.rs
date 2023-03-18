#![no_main]

use chksum_hash::sha2;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sha2::sha224::new().update(data).digest();
});
