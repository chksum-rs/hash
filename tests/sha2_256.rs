use chksum_hash::{default, hash, SHA2_256};

#[test]
fn hash_empty() {
    let digest = hash::<SHA2_256, _>("").to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = hash::<SHA2_256, _>(b"").to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = hash::<SHA2_256, _>(b"".to_vec()).to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn new_empty() {
    let digest = default::<SHA2_256>().digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = default::<SHA2_256>().update("").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = default::<SHA2_256>().update(b"").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let digest = default::<SHA2_256>().update(b"".to_vec()).digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hash_hello_world() {
    let digest = hash::<SHA2_256, _>("Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = hash::<SHA2_256, _>(b"Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = hash::<SHA2_256, _>(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );
}

#[test]
fn new_hello_world() {
    let digest = default::<SHA2_256>().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = default::<SHA2_256>()
        .update(b"Hello World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = default::<SHA2_256>()
        .update(b"Hello World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = default::<SHA2_256>()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = default::<SHA2_256>()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = default::<SHA2_256>()
        .update(b"Hello".to_vec())
        .update(b" ".to_vec())
        .update(b"World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    let digest = default::<SHA2_256>()
        .update("Hello")
        .update(b" ")
        .update(b"World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );
}
