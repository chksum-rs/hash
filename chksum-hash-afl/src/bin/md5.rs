use afl::fuzz;
use chksum_hash::md5;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = md5::new().update(data).digest();
    });
}
