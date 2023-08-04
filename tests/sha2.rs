mod sha224 {
    use chksum_hash::sha2::sha224;

    #[test]
    fn test_empty() {
        let digest = sha224::hash("");
        assert_eq!(
            digest.to_hex_lowercase(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );

        let digest = sha224::new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn test_hello_world() {
        let digest = sha224::hash("Hello World!");
        assert_eq!(
            digest.to_hex_lowercase(),
            "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b"
        );

        let digest = sha224::new().update("Hello").update(" ").update("World!").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "4575bb4ec129df6380cedde6d71217fe0536f8ffc4e18bca530a7a1b"
        );
    }
}

mod sha256 {
    use chksum_hash::sha2::sha256;

    #[test]
    fn test_empty() {
        let digest = sha256::hash("");
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let digest = sha256::new().digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_hello_world() {
        let digest = sha256::hash("Hello World!");
        assert_eq!(
            digest.to_hex_lowercase(),
            "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        );

        let digest = sha256::new().update("Hello").update(" ").update("World!").digest();
        assert_eq!(
            digest.to_hex_lowercase(),
            "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        );
    }
}

mod sha384 {
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
}

mod sha512 {
    use chksum_hash::sha2::sha512;

    #[test]
    fn test_empty() {
        let digest = sha512::hash("");
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

        let digest = sha512::new().digest();
        assert_eq!(digest.to_hex_lowercase(), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    }

    #[test]
    fn test_hello_world() {
        let digest = sha512::hash("Hello World!");
        assert_eq!(digest.to_hex_lowercase(), "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8");

        let digest = sha512::new().update("Hello").update(" ").update("World!").digest();
        assert_eq!(digest.to_hex_lowercase(), "861844d6704e8573fec34d967e20bcfef3d424cf48be04e6dc08f2bd58c729743371015ead891cc3cf1c9d34b49264b510751b1ff9e537937bc46b5d6ff4ecc8");
    }
}
