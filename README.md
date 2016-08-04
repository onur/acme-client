# letsencrypt-rs

[![Build Status](https://secure.travis-ci.org/onur/letsencrypt-rs.svg?branch=master)](https://travis-ci.org/onur/letsencrypt-rs)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/onur/letsencrypt-rs/master/LICENSE)

Easy to use Let's Encrypt client and acme client library to issue and renew
TLS certs.

## Installation

letsencrypt-rs can be installed with: `cargo install letsencrypt-rs`


## Usage

letsencrypt-rs is using openssl library to generate all required keys
and certificate signing request. You don't need to run any openssl command.
But also you can use your already generated keys and CSR if you want.
You don't need any root access while running letsencrypt-rs.

letsencrypt-rs is using simple HTTP validation to pass Let's Encrypt DNS
validation challenge. You need a working HTTP server to host challenge file.


### Easiest way to sign a certificate

```sh
letsencrypt-rs -D example.org -P /var/www -K domain.key -o domain.crt
```

This command will generate a user key, domain key and X509 certificate signing
request. It will register a new user account and identify domain ownership
by putting required challenge token into `/var/www/.well-known/acme-challenge/`.
And if everything goes well, it will save domain private key into `domain.key`
file and signed certificate into `domain.crt`.

You can also use `--email` option to provide a contact addres on registration.



### Using your own keys and CSR

You can use your own RSA keys for user registration and domain. For example:

```sh
letsencrypt-rs \
  --user-key user.key \
  --domain-key domain.key \
  --domain-csr domain.csr \
  --domain example.org \
  -P /var/www \
  -o domain.crt
```

This will not generate any key and it will use provided keys to sign
certificate.


## Options

You can get list of all available options with `letsencrypt-rs --help`:

```
letsencrypt-rs 0.1.0
Easy to use Let's Encrypt client to issue and renew TLS certs

USAGE:
    letsencrypt-rs [FLAGS] [OPTIONS] --domain <DOMAIN> --public-dir <PUBLIC_DIR>

FLAGS:
    -c, --chain      Chains the signed certificate with Let's Encrypt Authority X3 (IdenTrust
                     cross-signed) intermediate certificate.
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --bit-length <BIT_LENGHT>               Set bit length for CSR. Default is 2048.
    -D, --domain <DOMAIN>                       Name of domain for identification.
    -C, --domain-csr <DOMAIN_CSR>               Path of domain certificate signing request.
        --domain-key <DOMAIN_KEY_PATH>          Domain private key path to use it in CSR
                                                generation.
    -E, --email <EMAIL>                         Contact email address (optional).
    -P, --public-dir <PUBLIC_DIR>               Directory to save ACME simple http challenge.
        --save-csr <SAVE_DOMAIN_CSR>            Path to save domain certificate signing request.
    -K, --save-domain-key <SAVE_DOMAIN_KEY>     Path to save domain private key.
    -o, --save-crt <SAVE_SIGNED_CERTIFICATE>    Path to save signed certificate. Default is STDOUT.
    -U, --save-user-key <SAVE_USER_KEY>         Path to save private user key.
        --user-key <USER_KEY_PATH>              User private key path to use it in account
                                                registration.
```


## `acme-client` crate

`letsencrypt-rs` is powered by acme-client library. You can read documentation
in [docs.rs](https://docs.rs/acme-client). An example of `AcmeClient`:

```rust
AcmeClient::new()
    .set_domain("example.org")
    .register_account(Some("contact@example.org"))
    .and_then(|ac| ac.identify_domain())
    .and_then(|ac| ac.save_http_challenge_into("/var/www"))
    .and_then(|ac| ac.simple_http_validation())
    .and_then(|ac| ac.sign_certificate())
    .and_then(|ac| ac.save_domain_private_key("domain.key"))
    .and_then(|ac| ac.save_signed_certificate("domain.crt"));
```


## TODO

* Revoke certificate.
