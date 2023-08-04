use chksum_hash::sha2::sha384;

#[test]
fn test_empty() {
    let digest = sha384::hash("");
    assert_eq!(
        digest.to_hex_lowercase(),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let digest = sha384::new().digest();
    assert_eq!(
        digest.to_hex_lowercase(),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
}

#[test]
fn test_hello_world() {
    let digest = sha384::hash("Hello World!");
    assert_eq!(
        digest.to_hex_lowercase(),
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );

    let digest = sha384::new().update("Hello").update(" ").update("World!").digest();
    assert_eq!(
        digest.to_hex_lowercase(),
        "bfd76c0ebbd006fee583410547c1887b0292be76d582d96c242d2a792723e3fd6fd061f9d5cfd13b8f961358e6adba4a"
    );
}
