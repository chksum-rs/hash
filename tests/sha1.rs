use chksum_hash::sha1;

#[test]
fn hash_empty() {
    let digest = sha1::hash("").to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = sha1::hash(b"").to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = sha1::hash(vec![]).to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn new_empty() {
    let digest = sha1::new().digest().to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = sha1::new().update("").digest().to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = sha1::new().update(b"").digest().to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = sha1::new().update(vec![]).digest().to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn hash_hello_world() {
    let digest = sha1::hash("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::hash(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::hash(vec![
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
    ])
    .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");
}

#[test]
fn new_hello_world() {
    let digest = sha1::new().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::new().update(b"Hello World!").digest().to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::new()
        .update(vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::new()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::new()
        .update(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])
        .update(vec![0x20])
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = sha1::new()
        .update("Hello")
        .update(b" ")
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");
}
