# acme-client

[![Build Status](https://secure.travis-ci.org/onur/acme-client.svg?branch=master)](https://travis-ci.org/onur/acme-client)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/onur/acme-client/master/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/acme-client.svg)](https://crates.io/crates/acme-client)
[![docs.rs.io](https://docs.rs/acme-client/badge.svg)](https://docs.rs/acme-client)

Easy to use Let's Encrypt compatible ACME client to issue, renew and
revoke TLS certificates.

**Contents**

   * [CLI](#cli)
      * [Installation](#installation)
      * [Usage](#usage)
         * [Sign a certificate](#sign-a-certificate)
         * [Using your own keys and CSR](#using-your-own-keys-and-csr)
         * [Using DNS validation](#using-dns-validation)
         * [Revoking a signed certificate](#revoking-a-signed-certificate)
      * [Options](#options)
   * [Library](#library)
      * [API overview](#api-overview)
      * [Account registration](#account-registration)
      * [Identifying ownership of domain name](#identifying-ownership-of-domain-name)
         * [Identifier validation challenges](#identifier-validation-challenges)
            * [HTTP challenge](#http-challenge)
            * [DNS challenge:](#dns-challenge)
      * [Signing a certificate](#signing-a-certificate)
      * [Revoking a signed certificate](#revoking-a-signed-certificate-1)
      * [References](#references)


## Installation

By default acme-client crate comes with a handy CLI.
You can install acme-client with: `cargo install acme-client`


## Usage

acme-client is using the OpenSSL library to generate all required keys
and certificate signing request. You don't need to run any openssl command.
You can use your already generated keys and CSR if you want and you don't need
any root access while running acme-client.

acme-client is using simple HTTP validation to pass Let's Encrypt's DNS
validation challenge. You need a working HTTP server to host the challenge file.


### Sign a certificate

```sh
acme-client sign -D example.org -P /var/www -k domain.key -o domain.crt
```

This command will generate a user key, domain key and X509 certificate signing
request. It will register a new user account and identify the domain ownership
by putting the required challenge token into `/var/www/.well-known/acme-challenge/`.
If everything goes well, it will save the domain private key into `domain.key`
and the signed certificate into `domain.crt`.

You can also use the `--email` option to provide a contact adress on registration.



### Using your own keys and CSR

You can use your own RSA keys for user registration and domain. For example:

```sh
acme-client sign \
  --user-key user.key \
  --domain-key domain.key \
  --domain-csr domain.csr \
  -P /var/www \
  -o domain.crt
```

This will not generate any key and it will use provided keys to sign
the certificate. It will also get domain names from provided CSR file.


### Using DNS validation

You can use `--dns` flag to trigger DNS validation instead of HTTP. This
option requires user to generate a TXT record for domain. An example DNS
validation:

```sh
$ acme-client sign --dns -D onur.im -E onur@onur.im \
    -k /tmp/onur.im.key -o /tmp/onur.im.crt
Please create a TXT record for _acme-challenge.onur.im: fDdTmWl4RMuGqj9acJiTC13hF6dVOZUNm3FujCIz3jc
Press enter to continue
```


### Revoking a signed certificate

acme-client can also revoke a signed certificate. You need to use your
user key and a signed certificate to revoke.

```sh
acme-client revoke --user-key user.key --signed-crt signed.crt
```


## Options

You can get a list of all available options with `acme-client sign --help`
and `acme-client revoke --help`:

```
$ acme-client sign --help
acme-client-sign
Signs a certificate

USAGE:
    acme-client sign [FLAGS] [OPTIONS]

FLAGS:
    -d, --dns        Use DNS challenge instead of HTTP. This option requires
                     user to generate a TXT record for domain.
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -A, --directory <DIRECTORY>
            Set ACME directory URL [default: https://acme-v01.api.letsencrypt.org/directory]
    -D, --domain <DOMAIN>...
            Domain name to obtain certificate. You can use more than one domain name.
    -P, --public-dir <PUBLIC_DIR>
            Directory to save ACME simple HTTP challenge. This option is
            required unless --dns option is being used.
    -U, --user-key <USER_KEY_PATH>
            Path to load user private key to use it in account registration.
            This is optional and acme-client will generate one if it's not supplied.
    -C, --csr <DOMAIN_CSR>
            Path to load domain certificate signing request. acme-client can also use CSR to get domain names.
            This is optional and acme-client will generate one if it's not supplied.
    -K, --domain-key <DOMAIN_KEY_PATH>
            Path to load private domain key.
            This is optional and acme-client will generate one if it's not supplied.
    -E, --email <EMAIL>
            Contact email address (optional).
    -c, --save-chained-crt <SAVE_CHAINED_CERTIFICATE>
            Chain signed certificate with Let's Encrypt Authority X3
            (IdenTrust cross-signed) intermediate certificate and save to given path.
    -r, --save-csr <SAVE_DOMAIN_CSR>
            Path to save domain certificate signing request generated by acme-client.
    -k, --save-domain-key <SAVE_DOMAIN_KEY>
            Path to save domain private key generated by acme-client.
    -i, --save-intermediate-crt <SAVE_INTERMEDIATE_CERTIFICATE>
            Path to save intermediate certificate.
    -o, --save-crt <SAVE_SIGNED_CERTIFICATE>
            Path to save signed certificate. Default is STDOUT.
    -u, --save-user-key <SAVE_USER_KEY>
            Path to save private user key.
```

```
$ acme-client revoke --help
acme-client-revoke
Revokes a signed certificate

USAGE:
    acme-client revoke --user-key <USER_KEY> --signed-crt <SIGNED_CRT>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -C, --signed-crt <SIGNED_CRT>    Path to signed domain certificate to revoke.
    -K, --user-key <USER_KEY>        User or domain private key path.
```

There is also `genkey` and `gencsr` subcommands to generate RSA private key
and CSR. You can use multiple `-v` flags for verbose output.


# Library

You can read entire API documentation in [docs.rs](https://docs.rs/acme-client).
You can use acme-client library by adding following lines to your `Cargo.toml`:

```toml
[dependencies]
acme-client = "0.5"
```

By default `acme-client` will build CLI. You can disable this with:

```toml
[dependencies.acme-client]
version = "0.5"
default-features = false
```


## API overview

To successfully sign a SSL certificate for a domain name, you need to identify ownership of
your domain. You can also identify and sign certificate for multiple domain names and
explicitly use your own private keys and certificate signing request (CSR),
otherwise this library will generate them. Basic usage of `acme-client`:

```rust,no_run
use acme_client::Directory;

let directory = Directory::lets_encrypt()?;
let account = directory.account_registration().register()?;

// Create a identifier authorization for example.com
let authorization = account.authorization("example.com")?;

// Validate ownership of example.com with http challenge
let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
http_challenge.save_key_authorization("/var/www")?;
http_challenge.validate()?;

let cert = account.certificate_signer(&["example.com"]).sign_certificate()?;
cert.save_signed_certificate("certificate.pem")?;
cert.save_private_key("certificate.key")?;
```

`acme-client` supports signing a certificate for multiple domain names with SAN. You need to
validate ownership of each domain name:

```rust,no_run
use acme_client::Directory;

let directory = Directory::lets_encrypt()?;
let account = directory.account_registration().register()?;

let domains = ["example.com", "example.org"];

for domain in domains.iter() {
    let authorization = account.authorization(domain)?;
    // ...
}

let cert = account.certificate_signer(&domains).sign_certificate()?;
cert.save_signed_certificate("certificate.pem")?;
cert.save_private_key("certificate.key")?;
```

## Account registration

```rust,no_run
use acme_client::Directory;

let directory = Directory::lets_encrypt()?;
let account = directory.account_registration()
                       .email("example@example.org")
                       .register()?;
```

Contact email address is optional. You can also use your own private key during
registration. See [AccountRegistration](https://docs.rs/acme-client/0.5/acme_client/struct.AccountRegistration.html) helper for more
details.

If you already registed with your own keys before, you still need to use
[`register`](https://docs.rs/acme-client/0.5/acme_client/struct.AccountRegistration.html#method.register) method,
in this case it will identify your user account instead of creating a new one.


## Identifying ownership of domain name

Before sending a certificate signing request to an ACME server, you need to identify ownership
of domain names you want to sign a certificate for. To do that you need to create an
Authorization object for a domain name and fulfill at least one challenge (http or dns for
Let's Encrypt).

To create an Authorization object for a domain:

```rust,no_run
let authorization = account.authorization("example.com")?;
```

[Authorization](https://docs.rs/acme-client/0.5/acme_client/struct.Authorization.html)
object will contain challenges created by ACME server. You can create as many
Authorization object as you want to verifiy ownership of the domain names. For example
if you want to sign a certificate for `example.com` and `example.org`:

```rust,no_run
let domains = ["example.com", "example.org"];
for domain in domains.iter() {
    let authorization = account.authorization(domain)?;
    // ...
}
```

### Identifier validation challenges

When you send authorization request to an ACME server, it will generate
identifier validation challenges to provide assurence that an account holder is also
the entity that controls an identifier.

#### HTTP challenge

With HTTP validation, the client in an ACME transaction proves its
control over a domain name by proving that it can provision resources
on an HTTP server that responds for that domain name.

`acme-client` has
[`save_key_authorization`](https://docs.rs/acme-client/0.5/acme_client/struct.Challenge.html#method.save_key_authorization) method
to save vaditation file to a public directory. This directory must be accessible to outside
world.

```rust,no_run
let authorization = account.authorization("example.com")?;
let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;

// This method will save key authorization into
// /var/www/.well-known/acme-challenge/ directory.
http_challenge.save_key_authorization("/var/www")?;

// Validate ownership of example.com with http challenge
http_challenge.validate()?;
```

During validation, ACME server will check
`http://example.com/.well-known/acme-challenge/{token}` to identify ownership of domain name.
You need to make sure token is publicly accessible.

#### DNS challenge:

The DNS challenge requires the client to provision a TXT record containing a designated
value under a specific validation domain name.

`acme-client` can generated this value with
[`signature`](https://docs.rs/acme-client/0.5/acme_client/struct.Challenge.html#method.signature) method.

The user constructs the validation domain name by prepending the label "_acme-challenge"
to the domain name being validated, then provisions a TXT record with the digest value under
that name. For example, if the domain name being validated is "example.com", then the client
would provision the following DNS record:

```text
_acme-challenge.example.com: dns_challenge.signature()
```

Example validation with DNS challenge:

```rust,no_run
let authorization = account.authorization("example.com")?;
let dns_challenge = authorization.get_dns_challenge().ok_or("DNS challenge not found")?;
let signature = dns_challenge.signature()?;

// User creates a TXT record for _acme-challenge.example.com with the value of signature.

// Validate ownership of example.com with DNS challenge
dns_challenge.validate()?;
```

## Signing a certificate

After validating all the domain names you can send a sign certificate request. `acme-client`
provides [`CertificateSigner`](https://docs.rs/acme-client/0.5/acme_client/struct.CertificateSigner.html) helper for this. You can
use your own key and CSR or you can let `CertificateSigner` to generate them for you.

```rust,no_run
let domains = ["example.com", "example.org"];

// ... validate ownership of domain names

let certificate_signer = account.certificate_signer(&domains);
let cert = certificate_signer.sign_certificate()?;
cert.save_signed_certificate("certificate.pem")?;
cert.save_private_key("certificate.key")?;
```

## Revoking a signed certificate

You can use `revoke_certificate` or `revoke_certificate_from_file` methods to revoke a signed
certificate. You need to register with the same private key you registered before to
successfully revoke a signed certificate. You can also use private key used to generate CSR.

```rust,no_run
let account = directory.account_registration()
                       .pkey_from_file("user.key")?
                       .register()?;
account.revoke_certificate_from_file("certificate.pem")?;
```

## References

* [IETF ACME draft](https://tools.ietf.org/html/draft-ietf-acme-acme-05)
* [Let's Encrypt ACME divergences](https://github.com/letsencrypt/boulder/blob/9c1e8e6764c1de195db6467057e0d148608e411d/docs/acme-divergences.md)
