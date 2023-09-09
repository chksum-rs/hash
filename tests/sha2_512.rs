use chksum_hash::{default, hash, SHA2_512};

#[test]
fn hash_empty() {
    let digest = hash::<SHA2_512, _>("").to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    let digest = hash::<SHA2_512, _>(b"").to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    let digest = hash::<SHA2_512, _>(b"".to_vec()).to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
}

#[test]
fn new_empty() {
    let digest = default::<SHA2_512>().digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    let digest = default::<SHA2_512>().update("").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    let digest = default::<SHA2_512>().update(b"").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );

    let digest = default::<SHA2_512>().update(b"".to_vec()).digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
}

#[test]
fn hash_hello_world() {
    let digest = hash::<SHA2_512, _>("Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = hash::<SHA2_512, _>(b"Hello World!").to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = hash::<SHA2_512, _>(b"Hello World!".to_vec()).to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );
}

#[test]
fn new_hello_world() {
    let digest = default::<SHA2_512>().update("Hello World!").digest().to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = default::<SHA2_512>()
        .update(b"Hello World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = default::<SHA2_512>()
        .update(b"Hello World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = default::<SHA2_512>()
        .update("Hello")
        .update(" ")
        .update("World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = default::<SHA2_512>()
        .update(b"Hello")
        .update(b" ")
        .update(b"World!")
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = default::<SHA2_512>()
        .update(b"Hello".to_vec())
        .update(b" ".to_vec())
        .update(b"World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );

    let digest = default::<SHA2_512>()
        .update("Hello")
        .update(b" ")
        .update(b"World!".to_vec())
        .digest()
        .to_hex_lowercase();
    assert_eq!(
        digest,
        "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8"
    );
}
