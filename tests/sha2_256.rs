use chksum_hash::sha2::sha256;

#[test]
fn test_empty() {
    let digest = sha256::hash("");
    assert_eq!(
        digest.to_hex_lowercase(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = sha256::new().digest();
    assert_eq!(
        digest.to_hex_lowercase(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn test_hello_world() {
    let digest = sha256::hash("Hello World!");
    assert_eq!(
        digest.to_hex_lowercase(),
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha256::new().update("Hello").update(" ").update("World!").digest();
    assert_eq!(
        digest.to_hex_lowercase(),
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );
}
