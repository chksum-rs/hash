use chksum_hash::sha2_384;

#[test]
fn hash_empty() {
    let digest = sha2_384::hash("").to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = sha2_384::hash(b"").to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = sha2_384::hash(vec![]).to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
}

#[test]
fn new_empty() {
    let digest = sha2_384::new().digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = sha2_384::new().update("").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = sha2_384::new().update(b"").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = sha2_384::new().update(vec![]).digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
}

#[test]
fn hash_hello_world() {
    let digest = sha2_384::hash("Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::hash(b"Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::hash(vec![
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
    ])
    .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );
}

#[test]
fn new_hello_world() {
    let digest = sha2_384::new().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::new().update(b"Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::new()
        .update(vec![
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ])
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::new()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::new()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::new()
        .update(vec![0x48, 0x65, 0x6C, 0x6C, 0x6F])
        .update(vec![0x20])
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha2_384::new()
        .update("Hello")
        .update(b" ")
        .update(vec![0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21])
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );
}
