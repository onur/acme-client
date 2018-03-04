//! Easy to use [Let's Encrypt](https://letsencrypt.org/) compatible
//! Automatic Certificate Management Environment (ACME) client.
//!
//! You can use acme-client library by adding following lines to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! acme-client = "0.5"
//! ```
//!
//! By default `acme-client` will build CLI. You can disable this with:
//!
//! ```toml
//! [dependencies.acme-client]
//! version = "0.5"
//! default-features = false
//! ```
//!
//! See <https://github.com/onur/acme-client> for CLI usage.
//!
//! ## API overview
//!
//! To successfully sign a SSL certificate for a domain name, you need to identify ownership of
//! your domain. You can also identify and sign certificate for multiple domain names and
//! explicitly use your own private keys and certificate signing request (CSR),
//! otherwise this library will generate them. Basic usage of `acme-client`:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration().register()?;
//!
//! // Create a identifier authorization for example.com
//! let authorization = account.authorization("example.com")?;
//!
//! // Validate ownership of example.com with http challenge
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
//! http_challenge.save_key_authorization("/var/www")?;
//! http_challenge.validate()?;
//!
//! let cert = account.certificate_signer(&["example.com"]).sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! `acme-client` supports signing a certificate for multiple domain names with SAN. You need to
//! validate ownership of each domain name:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration().register()?;
//!
//! let domains = ["example.com", "example.org"];
//!
//! for domain in domains.iter() {
//!     let authorization = account.authorization(domain)?;
//!     // ...
//! }
//!
//! let cert = account.certificate_signer(&domains).sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Account registration
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! use acme_client::Directory;
//!
//! let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration()
//!                        .email("example@example.org")
//!                        .register()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! Contact email address is optional. You can also use your own private key during
//! registration. See [AccountRegistration](struct.AccountRegistration.html) helper for more
//! details.
//!
//! If you already registed with your own keys before, you still need to use
//! [`register`](struct.AccountRegistration.html#method.register) method,
//! in this case it will identify your user account instead of creating a new one.
//!
//!
//! ## Identifying ownership of domain name
//!
//! Before sending a certificate signing request to an ACME server, you need to identify ownership
//! of domain names you want to sign a certificate for. To do that you need to create an
//! Authorization object for a domain name and fulfill at least one challenge (http or dns for
//! Let's Encrypt).
//!
//! To create an Authorization object for a domain:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt().unwrap();
//! # // Use staging directory for doc test
//! # let directory = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")
//! #   .unwrap();
//! # let account = directory.account_registration().register().unwrap();
//! let authorization = account.authorization("example.com")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! [Authorization](struct.Authorization.html) object will contain challenges created by
//! ACME server. You can create as many Authorization object as you want to verify ownership
//! of the domain names. For example if you want to sign a certificate for
//! `example.com` and `example.org`:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt().unwrap();
//! # let account = directory.account_registration().register().unwrap();
//! let domains = ["example.com", "example.org"];
//! for domain in domains.iter() {
//!     let authorization = account.authorization(domain)?;
//!     // ...
//! }
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ### Identifier validation challenges
//!
//! When you send authorization request to an ACME server, it will generate
//! identifier validation challenges to provide assurence that an account holder is also
//! the entity that controls an identifier.
//!
//! #### HTTP challenge
//!
//! With HTTP validation, the client in an ACME transaction proves its
//! control over a domain name by proving that it can provision resources
//! on an HTTP server that responds for that domain name.
//!
//! `acme-client` has
//! [`save_key_authorization`](struct.Challenge.html#method.save_key_authorization) method
//! to save vaditation file to a public directory. This directory must be accessible to outside
//! world.
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration()
//! #                        .pkey_from_file("tests/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let http_challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
//!
//! // This method will save key authorization into
//! // /var/www/.well-known/acme-challenge/ directory.
//! http_challenge.save_key_authorization("/var/www")?;
//!
//! // Validate ownership of example.com with http challenge
//! http_challenge.validate()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! During validation, ACME server will check
//! `http://example.com/.well-known/acme-challenge/{token}` to identify ownership of domain name.
//! You need to make sure token is publicly accessible.
//!
//! #### DNS challenge:
//!
//! The DNS challenge requires the client to provision a TXT record containing a designated
//! value under a specific validation domain name.
//!
//! `acme-client` can generated this value with
//! [`signature`](struct.Challenge.html#method.signature) method.
//!
//! The user constructs the validation domain name by prepending the label "_acme-challenge"
//! to the domain name being validated, then provisions a TXT record with the digest value under
//! that name. For example, if the domain name being validated is "example.com", then the client
//! would provision the following DNS record:
//!
//! ```text
//! _acme-challenge.example.com: dns_challenge.signature()
//! ```
//!
//! Example validation with DNS challenge:
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration()
//! #                        .pkey_from_file("tests/user.key")?  // use test key for doc test
//! #                        .register()?;
//! let authorization = account.authorization("example.com")?;
//! let dns_challenge = authorization.get_dns_challenge().ok_or("DNS challenge not found")?;
//! let signature = dns_challenge.signature()?;
//!
//! // User creates a TXT record for _acme-challenge.example.com with the value of signature.
//!
//! // Validate ownership of example.com with DNS challenge
//! dns_challenge.validate()?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Signing a certificate
//!
//! After validating all the domain names you can send a sign certificate request. `acme-client`
//! provides [`CertificateSigner`](struct.CertificateSigner.html) helper for this. You can
//! use your own key and CSR or you can let `CertificateSigner` to generate them for you.
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! # let account = directory.account_registration().register()?;
//! let domains = ["example.com", "example.org"];
//!
//! // ... validate ownership of domain names
//!
//! let certificate_signer = account.certificate_signer(&domains);
//! let cert = certificate_signer.sign_certificate()?;
//! cert.save_signed_certificate("certificate.pem")?;
//! cert.save_private_key("certificate.key")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## Revoking a signed certificate
//!
//! You can use `revoke_certificate` or `revoke_certificate_from_file` methods to revoke a signed
//! certificate. You need to register with the same private key you registered before to
//! successfully revoke a signed certificate. You can also use private key used to generate CSR.
//!
//! ```rust,no_run
//! # use acme_client::error::Result;
//! # fn try_main() -> Result<()> {
//! # use acme_client::Directory;
//! # let directory = Directory::lets_encrypt()?;
//! let account = directory.account_registration()
//!                        .pkey_from_file("user.key")?
//!                        .register()?;
//! account.revoke_certificate_from_file("certificate.pem")?;
//! # Ok(()) }
//! # fn main () { try_main().unwrap(); }
//! ```
//!
//! ## References
//!
//! * [IETF ACME draft](https://tools.ietf.org/html/draft-ietf-acme-acme-05)
//! * [Let's Encrypt ACME divergences](https://github.com/letsencrypt/boulder/blob/9c1e8e6764c1de195db6467057e0d148608e411d/docs/acme-divergences.md)

pub extern crate openssl;
#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate hyper;
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate base64;

use std::path::Path;
use std::fs::File;
use std::io::{Read, Write};
use std::collections::HashMap;

use openssl::sign::Signer;
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::PKey;
use openssl::x509::{X509, X509Req};

use reqwest::{Client, StatusCode};

use helper::{gen_key, b64, read_pkey, gen_csr};
use error::{Result, ErrorKind};

use serde_json::{Value, from_str, to_string, to_value};
use serde::Serialize;

/// Default Let's Encrypt directory URL to configure client.
pub const LETSENCRYPT_DIRECTORY_URL: &'static str = "https://acme-v01.api.letsencrypt.org\
                                                     /directory";
/// Default Let's Encrypt agreement URL used in account registration.
pub const LETSENCRYPT_AGREEMENT_URL: &'static str = "https://letsencrypt.org/documents/LE-SA-v1.2-\
                                                     November-15-2017.pdf";
/// Default Let's Encrypt intermediate certificate URL to chain when needed.
pub const LETSENCRYPT_INTERMEDIATE_CERT_URL: &'static str = "https://letsencrypt.org/certs/\
                                                             lets-encrypt-x3-cross-signed.pem";
/// Default bit lenght for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;


/// Directory object to configure client. Main entry point of `acme-client`.
///
/// See [section-6.1.1](https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-6.1.1)
/// for more details.
pub struct Directory {
    /// Base URL of directory
    url: String,
    directory: Value,
}

/// Registered account object.
///
/// Every operation requires a registered account. To register an `Account` you can use
/// `Directory::register_account` method.
///
/// See [AccountRegistration](struct.AccountRegistration.html) helper for more details.
pub struct Account {
    directory: Directory,
    pkey: PKey<openssl::pkey::Private>,
}


/// Helper to register an account.
pub struct AccountRegistration {
    directory: Directory,
    pkey: Option<PKey<openssl::pkey::Private>>,
    email: Option<String>,
    contact: Option<Vec<String>>,
    agreement: Option<String>,
}


/// Helper to sign a certificate.
pub struct CertificateSigner<'a> {
    account: &'a Account,
    domains: &'a [&'a str],
    pkey: Option<PKey<openssl::pkey::Private>>,
    csr: Option<X509Req>,
}


/// A signed certificate.
pub struct SignedCertificate {
    cert: X509,
    csr: X509Req,
    pkey: PKey<openssl::pkey::Private>,
}


/// Identifier authorization object.
pub struct Authorization<'a>(Vec<Challenge<'a>>);


/// A verification challenge.
pub struct Challenge<'a> {
    account: &'a Account,
    /// Type of verification challenge. Usually `http-01`, `dns-01` for letsencrypt.
    ctype: String,
    /// URL to trigger challenge.
    url: String,
    /// Challenge token.
    token: String,
    /// Key authorization.
    key_authorization: String,
}


impl Directory {
    /// Creates a Directory from
    /// [`LETSENCRYPT_DIRECTORY_URL`](constant.LETSENCRYPT_DIRECTORY_URL.html).
    pub fn lets_encrypt() -> Result<Directory> {
        Directory::from_url(LETSENCRYPT_DIRECTORY_URL)
    }

    /// Creates a Directory from directory URL.
    ///
    /// Example directory for testing `acme-client` crate with staging API:
    ///
    /// ```rust
    /// # use acme_client::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::Directory;
    /// let dir = Directory::from_url("https://acme-staging.api.letsencrypt.org/directory")?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn from_url(url: &str) -> Result<Directory> {
        let client = Client::new()?;
        let mut res = client.get(url).send()?;
        let mut content = String::new();
        res.read_to_string(&mut content)?;
        Ok(Directory {
               url: url.to_owned(),
               directory: from_str(&content)?,
           })

    }

    /// Returns url for the resource.
    fn url_for(&self, resource: &str) -> Option<&str> {
        self.directory
            .as_object()
            .and_then(|o| o.get(resource))
            .and_then(|k| k.as_str())
    }

    /// Consumes directory and creates new AccountRegistration.
    ///
    /// AccountRegistration is used to register an account.
    ///
    /// ```rust,no_run
    /// # use acme_client::error::Result;
    /// # fn try_main() -> Result<()> {
    /// use acme_client::Directory;
    ///
    /// let directory = Directory::lets_encrypt()?;
    /// let account = directory.account_registration()
    ///                        .email("example@example.org")
    ///                        .register()?;
    /// # Ok(()) }
    /// # fn main () { try_main().unwrap(); }
    /// ```
    pub fn account_registration(self) -> AccountRegistration {
        AccountRegistration {
            directory: self,
            pkey: None,
            email: None,
            contact: None,
            agreement: None,
        }
    }

    /// Gets nonce header from directory.
    ///
    /// This function will try to look for `new-nonce` key in directory if it doesn't exists
    /// it will try to get nonce header from directory url.
    fn get_nonce(&self) -> Result<String> {
        let url = self.url_for("new-nonce").unwrap_or(&self.url);
        let client = Client::new()?;
        let res = client.get(url).send()?;
        res.headers()
            .get::<hyperx::ReplayNonce>()
            .ok_or("Replay-Nonce header not found".into())
            .and_then(|nonce| Ok(nonce.as_str().to_string()))
    }

    /// Makes a new post request to directory, signs payload with pkey.
    ///
    /// Returns status code and Value object from reply.
    fn request<T: Serialize>(&self,
                             pkey: &PKey<openssl::pkey::Private>,
                             resource: &str,
                             payload: T)
                             -> Result<(StatusCode, Value)> {

        let mut json = to_value(&payload)?;

        let resource_json: Value = to_value(resource)?;
        json.as_object_mut()
            .and_then(|obj| obj.insert("resource".to_owned(), resource_json));

        let jws = self.jws(pkey, json)?;
        let client = Client::new()?;
        let mut res = client
            .post(self.url_for(resource)
                      .ok_or(format!("URL for resource: {} not found", resource))?)
            .body(&jws[..])
            .send()?;

        let res_json = {
            let mut res_content = String::new();
            res.read_to_string(&mut res_content)?;
            if !res_content.is_empty() {
                from_str(&res_content)?
            } else {
                to_value(true)?
            }
        };

        Ok((*res.status(), res_json))
    }

    /// Makes a Flattened JSON Web Signature from payload
    fn jws<T: Serialize>(&self, pkey: &PKey<openssl::pkey::Private>, payload: T) -> Result<String> {
        let nonce = self.get_nonce()?;
        let mut data: HashMap<String, Value> = HashMap::new();

        // header: 'alg': 'RS256', 'jwk': { e, n, kty }
        let mut header: HashMap<String, Value> = HashMap::new();
        header.insert("alg".to_owned(), to_value("RS256")?);
        header.insert("jwk".to_owned(), self.jwk(pkey)?);
        data.insert("header".to_owned(), to_value(&header)?);

        // payload: b64 of payload
        let payload = to_string(&payload)?;
        let payload64 = b64(&payload.into_bytes());
        data.insert("payload".to_owned(), to_value(&payload64)?);

        // protected: base64 of header + nonce
        header.insert("nonce".to_owned(), to_value(nonce)?);
        let protected64 = b64(&to_string(&header)?.into_bytes());
        data.insert("protected".to_owned(), to_value(&protected64)?);

        // signature: b64 of hash of signature of {proctected64}.{payload64}
        data.insert("signature".to_owned(), {
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
            signer
                .update(&format!("{}.{}", protected64, payload64).into_bytes())?;
            to_value(b64(&signer.sign_to_vec()?))?
        });

        let json_str = to_string(&data)?;
        Ok(json_str)
    }

    /// Returns jwk field of jws header
    fn jwk(&self, pkey: &PKey<openssl::pkey::Private>) -> Result<Value> {
        let rsa = pkey.rsa()?;
        let mut jwk: HashMap<String, String> = HashMap::new();
        jwk.insert("e".to_owned(),
                   b64(&rsa.e().to_vec()));
        jwk.insert("kty".to_owned(), "RSA".to_owned());
        jwk.insert("n".to_owned(),
                   b64(&rsa.n().to_vec()));
        Ok(to_value(jwk)?)
    }
}




impl Account {
    /// Creates a new identifier authorization object for domain
    pub fn authorization<'a>(&'a self, domain: &str) -> Result<Authorization<'a>> {
        info!("Sending identifier authorization request for {}", domain);

        let mut map = HashMap::new();
        map.insert("identifier".to_owned(), {
            let mut map = HashMap::new();
            map.insert("type".to_owned(), "dns".to_owned());
            map.insert("value".to_owned(), domain.to_owned());
            map
        });
        let (status, resp) = self.directory().request(self.pkey(), "new-authz", map)?;

        if status != StatusCode::Created {
            return Err(ErrorKind::AcmeServerError(resp).into());
        }

        let mut challenges = Vec::new();
        for challenge in resp.as_object()
                .and_then(|obj| obj.get("challenges"))
                .and_then(|c| c.as_array())
                .ok_or("No challenge found")? {

            let obj = challenge
                .as_object()
                .ok_or("Challenge object not found")?;

            let ctype = obj.get("type")
                .and_then(|t| t.as_str())
                .ok_or("Challenge type not found")?
                .to_owned();
            let uri = obj.get("uri")
                .and_then(|t| t.as_str())
                .ok_or("URI not found")?
                .to_owned();
            let token = obj.get("token")
                .and_then(|t| t.as_str())
                .ok_or("Token not found")?
                .to_owned();

            // This seems really cryptic but it's not
            // https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-7.1
            // key-authz = token || '.' || base64url(JWK\_Thumbprint(accountKey))
            let key_authorization = format!("{}.{}",
                                            token,
                                            b64(&hash(MessageDigest::sha256(),
                                                       &to_string(&self.directory()
                                                                       .jwk(self.pkey())?)?
                                                                .into_bytes())?));

            let challenge = Challenge {
                account: self,
                ctype: ctype,
                url: uri,
                token: token,
                key_authorization: key_authorization,
            };
            challenges.push(challenge);
        }

        Ok(Authorization(challenges))
    }

    /// Creates a new `CertificateSigner` helper to sign a certificate for list of domains.
    ///
    /// `domains` must be list of the domain names you want to sign a certificate for.
    /// Currently there is no way to retrieve subject alt names from a X509Req.
    ///
    /// You can additionally use your own private key and CSR.
    /// See [`CertificateSigner`](struct.CertificateSigner.html) for details.
    pub fn certificate_signer<'a>(&'a self, domains: &'a [&'a str]) -> CertificateSigner<'a> {
        CertificateSigner {
            account: self,
            domains: domains,
            pkey: None,
            csr: None,
        }
    }

    /// Revokes a signed certificate from pem formatted file
    pub fn revoke_certificate_from_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = {
            let mut file = File::open(path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        let cert = X509::from_pem(&content)?;
        self.revoke_certificate(&cert)
    }

    /// Revokes a signed certificate
    pub fn revoke_certificate(&self, cert: &X509) -> Result<()> {
        let (status, resp) = {
            let mut map = HashMap::new();
            map.insert("certificate".to_owned(), b64(&cert.to_der()?));

            self.directory()
                .request(self.pkey(), "revoke-cert", map)?
        };

        match status {
            StatusCode::Ok => info!("Certificate successfully revoked"),
            StatusCode::Conflict => warn!("Certificate already revoked"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        }

        Ok(())
    }

    /// Writes account private key to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Saves account private key to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Returns a reference to account private key
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }

    /// Returns a reference to directory used to create account
    pub fn directory(&self) -> &Directory {
        &self.directory
    }
}


impl AccountRegistration {
    /// Sets contact email address
    pub fn email(mut self, email: &str) -> AccountRegistration {
        self.email = Some(email.to_owned());
        self
    }

    /// Sets contact details such as telephone number (Let's Encrypt only supports email address).
    pub fn contact(mut self, contact: &[&str]) -> AccountRegistration {
        self.contact = Some(contact.iter().map(|c| c.to_string()).collect());
        self
    }

    /// Sets agreement url,
    /// [`LETSENCRYPT_AGREEMENT_URL`](constant.LETSENCRYPT_AGREEMENT_URL.html)
    /// will be used during registration if it's not set.
    pub fn agreement(mut self, url: &str) -> AccountRegistration {
        self.agreement = Some(url.to_owned());
        self
    }

    /// Sets account private key. A new key will be generated if it's not set.
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> AccountRegistration {
        self.pkey = Some(pkey);
        self
    }

    /// Sets PKey from a PEM formatted file.
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<AccountRegistration> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }

    /// Registers an account.
    ///
    /// A PKey will be generated if it doesn't exists.
    pub fn register(self) -> Result<Account> {
        info!("Registering account");
        let mut map = HashMap::new();
        map.insert("agreement".to_owned(),
                   to_value(self.agreement
                                .unwrap_or(LETSENCRYPT_AGREEMENT_URL.to_owned()))?);
        if let Some(mut contact) = self.contact {
            if let Some(email) = self.email {
                contact.push(format!("mailto:{}", email));
            }
            map.insert("contract".to_owned(), to_value(contact)?);
        } else if let Some(email) = self.email {
            map.insert("contract".to_owned(),
                       to_value(vec![format!("mailto:{}", email)])?);
        }

        let pkey = self.pkey.unwrap_or(gen_key()?);
        let (status, resp) = self.directory.request(&pkey, "new-reg", map)?;

        match status {
            StatusCode::Created => debug!("User successfully registered"),
            StatusCode::Conflict => debug!("User already registered"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        };

        Ok(Account {
               directory: self.directory,
               pkey: pkey,
           })
    }
}


impl<'a> CertificateSigner<'a> {
    /// Set PKey of CSR
    pub fn pkey(mut self, pkey: PKey<openssl::pkey::Private>) -> CertificateSigner<'a> {
        self.pkey = Some(pkey);
        self
    }

    /// Load PEM formatted PKey from file
    pub fn pkey_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(path)?);
        Ok(self)
    }

    /// Set CSR to sign
    pub fn csr(mut self, csr: X509Req) -> CertificateSigner<'a> {
        self.csr = Some(csr);
        self
    }

    /// Load PKey and CSR from file
    pub fn csr_from_file<P: AsRef<Path>>(mut self,
                                         pkey_path: P,
                                         csr_path: P)
                                         -> Result<CertificateSigner<'a>> {
        self.pkey = Some(read_pkey(pkey_path)?);
        let content = {
            let mut file = File::open(csr_path)?;
            let mut content = Vec::new();
            file.read_to_end(&mut content)?;
            content
        };
        self.csr = Some(X509Req::from_pem(&content)?);
        Ok(self)
    }


    /// Signs certificate.
    ///
    /// CSR and PKey will be generated if it doesn't set or loaded first.
    pub fn sign_certificate(self) -> Result<SignedCertificate> {
        info!("Signing certificate");
        let pkey = self.pkey.unwrap_or(gen_key()?);
        let csr = self.csr.unwrap_or(gen_csr(&pkey, self.domains)?);
        let mut map = HashMap::new();
        map.insert("resource".to_owned(), "new-cert".to_owned());
        map.insert("csr".to_owned(), b64(&csr.to_der()?));

        let client = Client::new()?;
        let jws = self.account.directory().jws(self.account.pkey(), map)?;
        let mut res = client
            .post(self.account
                      .directory()
                      .url_for("new-cert")
                      .ok_or("new-cert url not found")?)
            .body(&jws[..])
            .send()?;

        if res.status() != &StatusCode::Created {
            let res_json = {
                let mut res_content = String::new();
                res.read_to_string(&mut res_content)?;
                from_str(&res_content)?
            };
            return Err(ErrorKind::AcmeServerError(res_json).into());
        }

        let mut crt_der = Vec::new();
        res.read_to_end(&mut crt_der)?;
        let cert = X509::from_der(&crt_der)?;

        debug!("Certificate successfully signed");
        Ok(SignedCertificate {
               cert: cert,
               csr: csr,
               pkey: pkey,
           })
    }
}


impl SignedCertificate {
    /// Saves signed certificate to a file
    pub fn save_signed_certificate<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)
    }

    /// Saves intermediate certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_intermediate_certificate<P: AsRef<Path>>(&self,
                                                         url: Option<&str>,
                                                         path: P)
                                                         -> Result<()> {
        let mut file = File::create(path)?;
        self.write_intermediate_certificate(url, &mut file)
    }

    /// Saves intermediate certificate and signed certificate to a file
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn save_signed_certificate_and_chain<P: AsRef<Path>>(&self,
                                                             url: Option<&str>,
                                                             path: P)
                                                             -> Result<()> {
        let mut file = File::create(path)?;
        self.write_signed_certificate(&mut file)?;
        self.write_intermediate_certificate(url, &mut file)?;
        Ok(())
    }

    /// Saves private key used to sign certificate to a file
    pub fn save_private_key<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_private_key(&mut file)
    }

    /// Saves CSR used to sign certificateto to a file
    pub fn save_csr<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path)?;
        self.write_csr(&mut file)
    }

    /// Writes signed certificate to writer.
    pub fn write_signed_certificate<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.cert.to_pem()?)?;
        Ok(())
    }

    /// Writes intermediate certificate to writer.
    ///
    /// You can additionally provide intermediate certificate url, by default it will use
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    pub fn write_intermediate_certificate<W: Write>(&self,
                                                    url: Option<&str>,
                                                    writer: &mut W)
                                                    -> Result<()> {
        let cert = self.get_intermediate_certificate(url)?;
        writer.write_all(&cert.to_pem()?)?;
        Ok(())
    }

    /// Gets intermediate certificate from url.
    ///
    /// [`LETSENCRYPT_INTERMEDIATE_CERT_URL`](constant.LETSENCRYPT_INTERMEDIATE_CERT_URL.html).
    /// will be used if url is None.
    fn get_intermediate_certificate(&self, url: Option<&str>) -> Result<X509> {
        let client = Client::new()?;
        let mut res = client
            .get(url.unwrap_or(LETSENCRYPT_INTERMEDIATE_CERT_URL))
            .send()?;
        let mut content = Vec::new();
        res.read_to_end(&mut content)?;
        Ok(X509::from_pem(&content)?)
    }

    /// Writes private key used to sign certificate to a writer
    pub fn write_private_key<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.pkey().private_key_to_pem_pkcs8()?)?)
    }

    /// Writes CSR used to sign certificateto a writer
    pub fn write_csr<W: Write>(&self, writer: &mut W) -> Result<()> {
        Ok(writer.write_all(&self.csr().to_pem()?)?)
    }

    /// Returns reference to certificate
    pub fn cert(&self) -> &X509 {
        &self.cert
    }

    /// Returns reference to CSR used to sign certificate
    pub fn csr(&self) -> &X509Req {
        &self.csr
    }

    /// Returns reference to pkey used to sign certificate
    pub fn pkey(&self) -> &PKey<openssl::pkey::Private> {
        &self.pkey
    }
}


impl<'a> Authorization<'a> {
    /// Gets a challenge.
    ///
    /// Pattern is used in `starts_with` for type comparison.
    pub fn get_challenge(&self, pattern: &str) -> Option<&Challenge> {
        for challenge in &self.0 {
            if challenge.ctype().starts_with(pattern) {
                return Some(challenge);
            }
        }
        None
    }

    /// Gets http challenge
    pub fn get_http_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("http")
    }

    /// Gets dns challenge
    pub fn get_dns_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("dns")
    }

    /// Gets tls-sni challenge
    pub fn get_tls_sni_challenge(&self) -> Option<&Challenge> {
        self.get_challenge("tls-sni")
    }
}


impl<'a> Challenge<'a> {
    /// Saves key authorization into `{path}/.well-known/acme-challenge/{token}` for http challenge.
    pub fn save_key_authorization<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        use std::fs::create_dir_all;
        let path = path.as_ref().join(".well-known").join("acme-challenge");
        debug!("Saving validation token into: {:?}", &path);
        create_dir_all(&path)?;

        let mut file = File::create(path.join(&self.token))?;
        writeln!(&mut file, "{}", self.key_authorization)?;

        Ok(())
    }

    /// Gets DNS validation signature.
    ///
    /// This value is used for verification of domain over DNS. Signature must be saved
    /// as a TXT record for `_acme_challenge.example.com`.
    pub fn signature(&self) -> Result<String> {
        Ok(b64(&hash(MessageDigest::sha256(),
                     &self.key_authorization.clone().into_bytes())?))
    }

    /// Returns challenge type, usually `http-01` or `dns-01` for Let's Encrypt.
    pub fn ctype(&self) -> &str {
        &self.ctype
    }

    /// Returns challenge token
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns key_authorization
    pub fn key_authorization(&self) -> &str {
        &self.key_authorization
    }

    /// Triggers validation.
    pub fn validate(&self) -> Result<()> {
        info!("Triggering {} validation", self.ctype);
        let payload = {
            let map = {
                let mut map: HashMap<String, Value> = HashMap::new();
                map.insert("type".to_owned(), to_value(&self.ctype)?);
                map.insert("token".to_owned(), to_value(&self.token)?);
                map.insert("resource".to_owned(), to_value("challenge")?);
                map.insert("keyAuthorization".to_owned(),
                           to_value(&self.key_authorization)?);
                map
            };
            self.account.directory().jws(self.account.pkey(), map)?
        };

        let client = Client::new()?;
        let mut resp = client.post(&self.url).body(&payload[..]).send()?;

        let mut res_json: Value = {
            let mut res_content = String::new();
            resp.read_to_string(&mut res_content)?;
            from_str(&res_content)?
        };

        if resp.status() != &StatusCode::Accepted {
            return Err(ErrorKind::AcmeServerError(res_json).into());
        }

        loop {
            let status = res_json
                .as_object()
                .and_then(|o| o.get("status"))
                .and_then(|s| s.as_str())
                .ok_or("Status not found")?
                .to_owned();

            if status == "pending" {
                debug!("Status is pending, trying again...");
                let mut resp = client.get(&self.url).send()?;
                res_json = {
                    let mut res_content = String::new();
                    resp.read_to_string(&mut res_content)?;
                    from_str(&res_content)?
                };
            } else if status == "valid" {
                return Ok(());
            } else if status == "invalid" {
                return Err(ErrorKind::AcmeServerError(res_json).into());
            }

            use std::thread::sleep;
            use std::time::Duration;
            sleep(Duration::from_secs(2));
        }
    }
}


// header! is making a public struct,
// our custom header is private and only used privately in this module
mod hyperx {
    // ReplayNonce header for hyper
    header! { (ReplayNonce, "Replay-Nonce") => [String] }
}


/// Error and result types.
pub mod error {
    use std::io;
    use openssl;
    use hyper;
    use reqwest;
    use serde_json;

    error_chain! {
        types {
            Error, ErrorKind, ChainErr, Result;
        }

        links {
        }

        foreign_links {
            OpenSslErrorStack(openssl::error::ErrorStack);
            IoError(io::Error);
            HyperError(hyper::Error);
            ReqwestError(reqwest::Error);
            ValueParserError(serde_json::Error);
        }

        errors {
            AcmeServerError(resp: serde_json::Value) {
                description("Acme server error")
                    display("Acme server error: {}", acme_server_error_description(resp))
            }
        }
    }


    fn acme_server_error_description(resp: &serde_json::Value) -> String {
        if let Some(obj) = resp.as_object() {
            let t = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let detail = obj.get("detail").and_then(|d| d.as_str()).unwrap_or("");
            format!("{} {}", t, detail)
        } else {
            String::new()
        }
    }
}


/// Various helper functions.
pub mod helper {

    use std::path::Path;
    use std::fs::File;
    use std::io::Read;
    use openssl;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Req, X509Name};
    use openssl::x509::extension::SubjectAlternativeName;
    use openssl::stack::Stack;
    use openssl::hash::MessageDigest;
    use error::Result;


    /// Generates new PKey.
    pub fn gen_key() -> Result<PKey<openssl::pkey::Private>> {
        let rsa = Rsa::generate(super::BIT_LENGTH)?;
        let key = PKey::from_rsa(rsa)?;
        Ok(key)
    }


    /// base64 Encoding with URL and Filename Safe Alphabet.
    pub fn b64(data: &[u8]) -> String {
        ::base64::encode_config(data, ::base64::URL_SAFE_NO_PAD)
    }


    /// Reads PKey from Path.
    pub fn read_pkey<P: AsRef<Path>>(path: P) -> Result<PKey<openssl::pkey::Private>> {
        let mut file = File::open(path)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        let key = PKey::private_key_from_pem(&content)?;
        Ok(key)
    }



    /// Generates X509Req (CSR) from domain names.
    ///
    /// This function will generate a CSR and sign it with PKey.
    ///
    /// Returns X509Req and PKey used to sign X509Req.
    pub fn gen_csr(pkey: &PKey<openssl::pkey::Private>, domains: &[&str]) -> Result<X509Req> {
        if domains.is_empty() {
            return Err("You need to supply at least one or more domain names".into());
        }

        let mut builder = X509Req::builder()?;
        let name = {
            let mut name = X509Name::builder()?;
            name.append_entry_by_text("CN", domains[0])?;
            name.build()
        };
        builder.set_subject_name(&name)?;

        // if more than one domain name is supplied
        // add them as SubjectAlternativeName
        if domains.len() > 1 {
            let san_extension = {
                let mut san = SubjectAlternativeName::new();
                for domain in domains.iter() {
                    san.dns(domain);
                }
                san.build(&builder.x509v3_context(None))?
            };
            let mut stack = Stack::new()?;
            stack.push(san_extension)?;
            builder.add_extensions(&stack)?;
        }

        builder.set_pubkey(&pkey)?;
        builder.sign(pkey, MessageDigest::sha256())?;

        Ok(builder.build())
    }
}




#[cfg(test)]
mod tests {
    extern crate env_logger;
    use super::*;

    const LETSENCRYPT_STAGING_DIRECTORY_URL: &'static str = "https://acme-staging.api.letsencrypt.\
                                                             org/directory";

    fn test_acc() -> Result<Account> {
        Directory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL)?
            .account_registration()
            .pkey_from_file("tests/user.key")?
            .register()
    }

    #[test]
    fn test_gen_key() {
        assert!(gen_key().is_ok())
    }

    #[test]
    fn test_b64() {
        assert_eq!(b64(&"foobar".to_string().into_bytes()), "Zm9vYmFy");
    }

    #[test]
    fn test_read_pkey() {
        assert!(read_pkey("tests/user.key").is_ok());
    }

    #[test]
    fn test_gen_csr() {
        let pkey = gen_key().unwrap();
        assert!(gen_csr(&pkey, &["example.com"]).is_ok());
        assert!(gen_csr(&pkey, &["example.com", "sub.example.com"]).is_ok());
    }

    #[test]
    fn test_directory() {
        assert!(Directory::lets_encrypt().is_ok());

        let dir = Directory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL).unwrap();
        assert!(dir.url_for("new-reg").is_some());
        assert!(dir.url_for("new-authz").is_some());
        assert!(dir.url_for("new-cert").is_some());

        assert!(!dir.get_nonce().unwrap().is_empty());

        let pkey = gen_key().unwrap();
        assert!(dir.jwk(&pkey).is_ok());
        assert!(dir.jws(&pkey, true).is_ok());
    }

    #[test]
    fn test_account_registration() {
        let _ = env_logger::init();
        let dir = Directory::from_url(LETSENCRYPT_STAGING_DIRECTORY_URL).unwrap();
        assert!(dir.account_registration()
                    .pkey_from_file("tests/user.key")
                    .unwrap()
                    .register()
                    .is_ok());
    }

    #[test]
    fn test_authorization() {
        let _ = env_logger::init();
        let account = test_acc().unwrap();
        let auth = account.authorization("example.com").unwrap();
        assert!(!auth.0.is_empty());
        assert!(auth.get_challenge("http").is_some());
        assert!(auth.get_http_challenge().is_some());
        assert!(auth.get_dns_challenge().is_some());
        //assert!(auth.get_tls_sni_challenge().is_some());

        for challenge in auth.0 {
            assert!(!challenge.ctype.is_empty());
            assert!(!challenge.url.is_empty());
            assert!(!challenge.token.is_empty());
            assert!(!challenge.key_authorization.is_empty());
        }
    }

    // This test requires properly configured domain name and a http server
    // It will read TEST_DOMAIN and TEST_PUBLIC_DIR environment variables
    #[test]
    #[ignore]
    fn test_sign_certificate() {
        use std::env;
        let _ = env_logger::init();
        let account = test_acc().unwrap();
        let auth = account
            .authorization(&env::var("TEST_DOMAIN").unwrap())
            .unwrap();
        let http_challenge = auth.get_http_challenge().unwrap();
        assert!(http_challenge
                    .save_key_authorization(&env::var("TEST_PUBLIC_DIR").unwrap())
                    .is_ok());
        assert!(http_challenge.validate().is_ok());
        let cert = account
            .certificate_signer(&[&env::var("TEST_DOMAIN").unwrap()])
            .sign_certificate()
            .unwrap();
        account.revoke_certificate(cert.cert()).unwrap();
    }
}
