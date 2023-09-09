use chksum_hash::{default, hash, SHA1};

#[test]
fn hash_empty() {
    let digest = hash::<SHA1, _>("").to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = hash::<SHA1, _>(b"").to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = hash::<SHA1, _>(b"".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn new_empty() {
    let digest = default::<SHA1>().to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = default::<SHA1>().update("").to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = default::<SHA1>().update(b"").to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");

    let digest = default::<SHA1>().update(b"".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}

#[test]
fn hash_hello_world() {
    let digest = hash::<SHA1, _>("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = hash::<SHA1, _>(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = hash::<SHA1, _>(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");
}

#[test]
fn new_hello_world() {
    let digest = default::<SHA1>().update("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = default::<SHA1>().update(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = default::<SHA1>().update(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = default::<SHA1>()
        .update("Hello")
        .update(" ")
        .update("World!")
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = default::<SHA1>()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = default::<SHA1>()
        .update(b"Hello".to_vec())
        .update(b" ".to_vec())
        .update(b"World!".to_vec())
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");

    let digest = default::<SHA1>()
        .update("Hello")
        .update(b" ")
        .update(b"World!".to_vec())
        .to_hex_lowercase();
    assert_eq!(digest, "2ef7bde608ce5404e97d5f042f95f89f1c232871");
}
