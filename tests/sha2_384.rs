use chksum_hash::{default, hash, SHA2_384};

#[test]
fn hash_empty() {
    let digest = hash::<SHA2_384, _>("").to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = hash::<SHA2_384, _>(b"").to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = hash::<SHA2_384, _>(b"".to_vec()).to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
}

#[test]
fn new_empty() {
    let digest = default::<SHA2_384>().digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = default::<SHA2_384>().update("").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = default::<SHA2_384>().update(b"").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = default::<SHA2_384>().update(b"".to_vec()).digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
}

#[test]
fn hash_hello_world() {
    let digest = hash::<SHA2_384, _>("Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = hash::<SHA2_384, _>(b"Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = hash::<SHA2_384, _>(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );
}

#[test]
fn new_hello_world() {
    let digest = default::<SHA2_384>().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = default::<SHA2_384>()
        .update(b"Hello World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = default::<SHA2_384>()
        .update(b"Hello World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = default::<SHA2_384>()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = default::<SHA2_384>()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = default::<SHA2_384>()
        .update(b"Hello".to_vec())
        .update(b" ".to_vec())
        .update(b"World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = default::<SHA2_384>()
        .update("Hello")
        .update(b" ")
        .update(b"World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );
}
