use chksum_hash::md5;

#[test]
fn hash_empty() {
    let digest = md5::hash("").to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = md5::hash(b"").to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = md5::hash(vec![]).to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn new_empty() {
    let digest = md5::new().digest().to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = md5::new().update("").digest().to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = md5::new().update(b"").digest().to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = md5::new().update(vec![]).digest().to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn hash_hello_world() {
    let digest = md5::hash("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::hash(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::hash(vec![
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
    ])
    .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");
}

#[test]
fn new_hello_world() {
    let digest = md5::new().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::new().update(b"Hello World!").digest().to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::new()
        .update(vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::new()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::new()
        .update(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])
        .update(vec![0x20])
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = md5::new()
        .update("Hello")
        .update(b" ")
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");
}
