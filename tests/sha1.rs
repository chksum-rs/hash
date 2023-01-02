use chksum_hash::sha1;

#[test]
fn test_empty() {
    let digest = sha1::hash("");
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );

    let digest = sha1::new().digest();
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
}

#[test]
fn test_hello_world() {
    let digest = sha1::new().update("Hello World!").finalize().digest();
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "2ef7bde608ce5404e97d5f042f95f89f1c232871"
    );

    #[rustfmt::skip]
    let digest = sha1::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest();
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "2ef7bde608ce5404e97d5f042f95f89f1c232871"
    );
}
