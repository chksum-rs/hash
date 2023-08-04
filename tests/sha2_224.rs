use chksum_hash::sha2::sha224;

#[test]
fn test_empty() {
    let digest = sha224::hash("");
    assert_eq!(
        digest.to_hex_lowercase(),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );

    let digest = sha224::new().digest();
    assert_eq!(
        digest.to_hex_lowercase(),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
    );
}

#[test]
fn test_hello_world() {
    let digest = sha224::hash("Hello World!");
    assert_eq!(
        digest.to_hex_lowercase(),
        "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b"
    );

    let digest = sha224::new().update("Hello").update(" ").update("World!").digest();
    assert_eq!(
        digest.to_hex_lowercase(),
        "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b"
    );
}
