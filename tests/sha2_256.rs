use chksum_hash::sha2_256;

#[test]
fn hash_empty() {
    let digest = sha2_256::hash("").to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = sha2_256::hash(b"").to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = sha2_256::hash(vec![]).to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn new_empty() {
    let digest = sha2_256::new().digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = sha2_256::new().update("").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = sha2_256::new().update(b"").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = sha2_256::new().update(vec![]).digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hash_hello_world() {
    let digest = sha2_256::hash("Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::hash(b"Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::hash(vec![
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
    ])
    .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );
}

#[test]
fn new_hello_world() {
    let digest = sha2_256::new().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::new().update(b"Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::new()
        .update(vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ])
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::new()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::new()
        .update(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])
        .update(vec![0x20])
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = sha2_256::new()
        .update("Hello")
        .update(b" ")
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );
}
