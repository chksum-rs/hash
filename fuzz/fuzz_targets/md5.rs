#![no_main]

use chksum_hash::md5;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = md5::new().update(data).digest();
});
