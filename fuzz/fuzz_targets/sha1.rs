#![no_main]

use chksum_hash::sha1;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sha1::new().update(data).digest();
});
