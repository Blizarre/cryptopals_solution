![Test workflow status](https://github.com/Blizarre/cryptopals_solution/actions/workflows/rust.yml/badge.svg)

# Cryptopals Solution

Solutions to the [cryptopals](https://cryptopals.com) challenges in `Rust`. Just `cargo run` to check all the exercices that have been implemented, and `cargo test` for the unit tests.

It's still in progress!

## Build

You will need the `libcrypto` library, usually provided by the `openssl` package of your distribution. This library is used to provide
the basic AES encryption/decryption routines for single blocks.

```shell
cargo build
```