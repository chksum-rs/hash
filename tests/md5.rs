use chksum_hash::md5;

#[test]
fn test_empty() {
    let digest = md5::hash("");
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "d41d8cd98f00b204e9800998ecf8427e"
    );

    let digest = md5::new().digest();
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "d41d8cd98f00b204e9800998ecf8427e"
    );
}

#[test]
fn test_hello_world() {
    let digest = md5::hash("Hello World!");
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "ed076287532e86365e841e92bfc50d8c"
    );

    #[rustfmt::skip]
    let digest = md5::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest();
    #[rustfmt::skip]
    assert_eq!(
        digest.to_hex_lowercase(),
        "ed076287532e86365e841e92bfc50d8c"
    );
}
