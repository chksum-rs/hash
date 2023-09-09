use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

use chksum_hash::sha2_224;

fn main() -> io::Result<()> {
    // Skip the first argument because it is not necessary to calculate digest of the binary itself
    for arg in env::args().skip(1) {
        // Create a new hash instance
        let mut hash = sha2_224::new();

        // Open the file
        let file = File::open(&arg)?;
        // Wrap it with a buffered reader
        let mut reader = BufReader::new(file);
        // Loop until there is data to process
        loop {
            // Take bytes from the file
            let buffer = reader.fill_buf()?;
            let length = buffer.len();
            // If EOF is reached, stop the loop
            if length == 0 {
                break;
            }
            // Consume the data
            hash = hash.update(buffer);
            reader.consume(length);
        }

        let digest = hash.to_hex_lowercase();

        println!("{arg} {digest}");
    }

    Ok(())
}
