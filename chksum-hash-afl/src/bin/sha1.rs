use afl::fuzz;
use chksum_hash::sha1;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = sha1::new().update(data).digest();
    });
}
