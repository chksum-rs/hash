use afl::fuzz;
use chksum_hash::sha2;

fn main() {
    fuzz!(|data: &[u8]| {
        let _ = sha2::sha512::new().update(data).digest();
    });
}
