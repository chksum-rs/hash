use chksum_hash::sha2_224;

#[test]
fn hash_empty() {
    let digest = sha2_224::hash("").to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

    let digest = sha2_224::hash(b"").to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

    let digest = sha2_224::hash(vec![]).to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
}

#[test]
fn new_empty() {
    let digest = sha2_224::new().digest().to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

    let digest = sha2_224::new().update("").digest().to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

    let digest = sha2_224::new().update(b"").digest().to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

    let digest = sha2_224::new().update(vec![]).digest().to_hex_lowercase();
    assert_eq!(digest, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
}

#[test]
fn hash_hello_world() {
    let digest = sha2_224::hash("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::hash(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::hash(vec![
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
    ])
    .to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");
}

#[test]
fn new_hello_world() {
    let digest = sha2_224::new().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::new().update(b"Hello World!").digest().to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::new()
        .update(vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::new()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::new()
        .update(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])
        .update(vec![0x20])
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");

    let digest = sha2_224::new()
        .update("Hello")
        .update(b" ")
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b");
}
