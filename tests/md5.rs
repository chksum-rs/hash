use chksum_hash::{default, hash, MD5};

#[test]
fn hash_empty() {
    let digest = hash::<MD5, _>("").to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = hash::<MD5, _>(b"").to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = hash::<MD5, _>(b"".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn new_empty() {
    let digest = default::<MD5>().to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = default::<MD5>().update("").to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = default::<MD5>().update(b"").to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");

    let digest = default::<MD5>().update(b"".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
}

#[test]
fn hash_hello_world() {
    let digest = hash::<MD5, _>("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = hash::<MD5, _>(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = hash::<MD5, _>(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");
}

#[test]
fn new_hello_world() {
    let digest = default::<MD5>().update("Hello World!").to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = default::<MD5>().update(b"Hello World!").to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = default::<MD5>().update(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = default::<MD5>()
        .update("Hello")
        .update(" ")
        .update("World!")
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = default::<MD5>()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = default::<MD5>()
        .update(b"Hello".to_vec())
        .update(b" ".to_vec())
        .update(b"World!".to_vec())
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");

    let digest = default::<MD5>()
        .update("Hello")
        .update(b" ")
        .update(b"World!".to_vec())
        .to_hex_lowercase();
    assert_eq!(digest, "ed076287532e86365e841e92bfc50d8c");
}
