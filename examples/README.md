# Examples

Simply run the following code:

```shell
cargo run --example md5 PATH/TO/FILE
```

All examples accept multiple arguments:

```shell
$ cargo run --example sha2_224 Cargo.toml LICENSE
Cargo.toml 10960544fea6342d6c8b69e938261d4226295b6a05c8e7a394fe4e0f
LICENSE 2d05dddbdc86b064e0b130ba403194125cb59ce80500e33d9018cbe4
```

## Limitations

You cannot pass paths to directories, nor can you calculate a digest from stdin.
