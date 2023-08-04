use chksum_hash::sha2::sha512;

#[test]
fn test_empty() {
    let digest = sha512::hash("");
    assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    let digest = sha512::new().digest();
    assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

#[test]
fn test_hello_world() {
    let digest = sha512::hash("Hello World!");
    assert_eq!(digest.to_hex_lowercase(), "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8");

    let digest = sha512::new().update("Hello").update(" ").update("World!").digest();
    assert_eq!(digest.to_hex_lowercase(), "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8");
}
