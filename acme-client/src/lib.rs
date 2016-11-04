//! Easy to use Let's Encrypt compatible Automatic Certificate Management Environment (ACME)
//! client library.
//!
//! Spec is available in <https://tools.ietf.org/html/draft-ietf-acme-acme>
//!
//! ## Examples
//!
//! Signing certificate for example.org:
//!
//! ```rust,no_run
//! # use self::acme_client::AcmeClient;
//! AcmeClient::new()
//!     .and_then(|ac| ac.set_domain("example.org"))
//!     .and_then(|ac| ac.register_account(Some("contact@example.org")))
//!     .and_then(|ac| ac.identify_domain())
//!     .and_then(|ac| ac.save_http_challenge_into("/var/www"))
//!     .and_then(|ac| ac.simple_http_validation())
//!     .and_then(|ac| ac.sign_certificate())
//!     .and_then(|ac| ac.save_domain_private_key("domain.key"))
//!     .and_then(|ac| ac.save_signed_certificate("domain.crt"));
//! ```
//!
//! Using your own keys and CSR to sign certificate:
//!
//! ```rust,no_run
//! # use self::acme_client::AcmeClient;
//! AcmeClient::new()
//!     .and_then(|ac| ac.set_domain("example.org"))
//!     .and_then(|ac| ac.load_user_key("user.key"))
//!     .and_then(|ac| ac.load_domain_key("domain.key"))
//!     .and_then(|ac| ac.load_csr("domain.csr"))
//!     .and_then(|ac| ac.register_account(Some("contact@example.org")))
//!     .and_then(|ac| ac.identify_domain())
//!     .and_then(|ac| ac.save_http_challenge_into("/var/www"))
//!     .and_then(|ac| ac.simple_http_validation())
//!     .and_then(|ac| ac.sign_certificate())
//!     .and_then(|ac| ac.save_domain_private_key("domain.key"))
//!     .and_then(|ac| ac.save_signed_certificate("domain.crt"));
//! ```
//!
//! Or you can use this library to generate keys and CSR, and use it later:
//!
//! ```rust
//! # use self::acme_client::AcmeClient;
//! AcmeClient::new()
//!     .and_then(|ac| ac.set_domain("example.org"))
//!     .and_then(|ac| ac.gen_user_key())
//!     .and_then(|ac| ac.gen_domain_key())
//!     .and_then(|ac| ac.gen_csr())
//!     .and_then(|ac| ac.save_user_public_key("user.pub"))
//!     .and_then(|ac| ac.save_user_private_key("user.pub"))
//!     .and_then(|ac| ac.save_domain_public_key("domain.pub"))
//!     .and_then(|ac| ac.save_domain_private_key("domain.key"))
//!     .and_then(|ac| ac.save_csr("domain.csr"));
//! ```
//!
//! Revoking signed certificate:
//! 
//! ```rust,no_run
//! # use self::acme_client::AcmeClient;
//! AcmeClient::new()
//!     .and_then(|ac| ac.load_user_key("tests/user.key"))
//!     .and_then(|ac| ac.load_certificate("domain.crt"))
//!     .and_then(|ac| ac.revoke_signed_certificate());
//! ```


#[macro_use]
extern crate log;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate hyper;
extern crate openssl;
extern crate rustc_serialize;


use std::fs::File;
use std::path::{Path, PathBuf};
use std::io;
use std::io::{Read, Write};
use std::collections::BTreeMap;

use openssl::crypto::rsa::RSA;
use openssl::crypto::pkey::PKey;
use openssl::crypto::hash::{hash, Type};
use openssl::x509::{X509, X509Req, X509Generator};
use openssl::x509::extension::{Extension, KeyUsageOption};

use hyper::Client;
use hyper::status::StatusCode;

use rustc_serialize::base64;
use rustc_serialize::base64::ToBase64;
use rustc_serialize::json::{Json, ToJson, encode};


/// Default bit lenght for RSA keys and `X509_REQ`
const BIT_LENGTH: u32 = 2048;

const LETSENCRYPT_CA_SERVER: &'static str = "https://acme-v01.api.letsencrypt.org";
const LETSENCRYPT_AGREEMENT: &'static str = "https://letsencrypt.org/documents/LE-SA-v1.1.\
                                             1-August-1-2016.pdf";



// header! is making a public struct,
// our custom header is private and only used privately in this module
mod hyperx {
    // ReplayNonce header for hyper
    header! { (ReplayNonce, "Replay-Nonce") => [String] }
}



/// Automatic Certificate Management Environment (ACME) client
pub struct AcmeClient {
    ca_server: String,
    agreement: String,
    bit_length: u32,
    user_key: Option<PKey>,
    domain: Option<String>,
    domain_key: Option<PKey>,
    domain_csr: Option<X509Req>,
    challenges: Option<Json>,
    http_challenge: Option<(String, String, String)>,
    signed_cert: Option<X509>,
    chain_url: Option<String>,
    saved_challenge_path: Option<PathBuf>,
}


impl Default for AcmeClient {
    fn default() -> Self {
        AcmeClient {
            ca_server: LETSENCRYPT_CA_SERVER.to_owned(),
            agreement: LETSENCRYPT_AGREEMENT.to_owned(),
            bit_length: BIT_LENGTH,
            user_key: None,
            domain: None,
            domain_key: None,
            domain_csr: None,
            challenges: None,
            http_challenge: None,
            signed_cert: None,
            chain_url: None,
            saved_challenge_path: None,
        }
    }
}


impl AcmeClient {
    pub fn new() -> Result<Self> {
        Ok(AcmeClient::default())
    }


    /// Sets domain name.
    pub fn set_domain(mut self, domain: &str) -> Result<Self> {
        self.domain = Some(domain.to_owned());
        Ok(self)
    }


    /// Sets CA server, default is: `https://acme-v01.api.letsencrypt.org`
    pub fn set_ca_server(mut self, ca_server: &str) -> Result<Self> {
        self.ca_server = ca_server.to_owned();
        Ok(self)
    }


    /// Sets intermediate PEM certificate URL to chain signed certificate with before
    /// `save_signed_certificate` and `write_signed_certificate`.
    ///
    /// Let's Encrypt intermediate certificates can be found in
    /// [certificates page](https://letsencrypt.org/certificates/).
    ///
    /// Let's Encrypt Authority X3 (IdenTrust cross-signed) certificate URL is:
    /// `https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem`
    pub fn set_chain_url(mut self, url: &str) -> Result<Self> {
        self.chain_url = Some(url.to_owned());
        Ok(self)
    }


    /// Generates new user key.
    pub fn gen_user_key(mut self) -> Result<Self> {
        debug!("Generating user key");
        if self.user_key.is_none() {
            self.user_key = Some(try!(gen_key(self.bit_length)));
        }
        Ok(self)
    }


    /// Generates new domain key.
    pub fn gen_domain_key(mut self) -> Result<Self> {
        debug!("Generating domain key");
        if self.domain_key.is_none() {
            self.domain_key = Some(try!(gen_key(self.bit_length)));
        }
        Ok(self)
    }


    /// Sets user aggrement.
    ///
    /// This agreement is used in user registration and user must agree this agreement. Default is:
    /// [LE-SA-v1.1.1-August-1-2016.pdf](https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf)
    ///
    /// Let's Encrypt requires an URL to agreed user agrement.
    pub fn set_agreement(mut self, agreement: &str) -> Result<Self> {
        self.agreement = agreement.to_owned();
        Ok(self)
    }

    /// Loads private key from PEM file path.
    pub fn load_user_key<P: AsRef<Path>>(mut self, private_key_path: P) -> Result<Self> {
        self.user_key = Some(try!(load_private_key(private_key_path)));
        Ok(self)
    }


    /// Loads private domain key from  PEM file path.
    pub fn load_domain_key<P: AsRef<Path>>(mut self, private_key_path: P) -> Result<Self> {
        self.domain_key = Some(try!(load_private_key(private_key_path)));
        Ok(self)
    }

    /// Gets the public key as PEM.
    pub fn get_user_public_key(self) -> Result<Vec<u8>> {
        self.user_key
            .as_ref()
            .ok_or("Key not found".into())
            .and_then(|k| pem_encode_key(k, true))
    }
 
    /// Gets the private key as PEM.
    pub fn get_user_private_key(self) -> Result<Vec<u8>> {
        self.user_key
            .as_ref()
            .ok_or("Key not found".into())
            .and_then(|k| pem_encode_key(k, false))
    }

    /// Gets domain public key as PEM.
    pub fn get_domain_public_key(self) -> Result<Vec<u8>> {
        self.domain_key
            .as_ref()
            .ok_or("Key not found".into())
            .and_then(|k| pem_encode_key(k, true))
    }


    /// Gets domain private key as PEM.
    pub fn get_domain_private_key(self) -> Result<Vec<u8>> {
        self.domain_key
            .as_ref()
            .ok_or("Key not found".into())
            .and_then(|k| pem_encode_key(k, false))
    }

    /// Saves user public key as PEM.
    pub fn save_user_public_key<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        try!(self.user_key
             .as_ref()
             .ok_or("Key not found".into())
             .and_then(|k| save_key(k, true, path)));
        Ok(self)
    }


    /// Saves user private key as PEM.
    pub fn save_user_private_key<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        try!(self.user_key
             .as_ref()
             .ok_or("Key not found".into())
             .and_then(|k| save_key(k, false, path)));
        Ok(self)
    }


    /// Saves domain public key as PEM.
    pub fn save_domain_public_key<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        try!(self.domain_key
             .as_ref()
             .ok_or("Key not found".into())
             .and_then(|k| save_key(k, true, path)));
        Ok(self)
    }


    /// Saves domain private key as PEM.
    pub fn save_domain_private_key<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        try!(self.domain_key
             .as_ref()
             .ok_or("Key not found".into())
             .and_then(|k| save_key(k, false, path)));
        Ok(self)
    }


    /// Sets bit lenght for CSR generation. Only 1024, 2048 and 4096 allowed.
    ///
    /// Default is 2048.
    pub fn set_bit_length(mut self, bit_length: u32) -> Result<Self> {
        match bit_length {
            1024 | 2048 | 4096 => self.bit_length = bit_length,
            _ => return Err("Invalid bit length. Only 1024 2048 and 4096 allowed".into()),
        }
        Ok(self)
    }


    /// Generates new certificate signing request for domain.
    ///
    /// You need to set a domain name with `domain()` first.
    pub fn gen_csr(mut self) -> Result<Self> {
        self = try!(self.gen_domain_key());
        let domain =
            try!(self.domain.clone().ok_or("Domain not found. Use domain() to set a domain"));
        let generator = X509Generator::new()
            .set_valid_period(365)
            .add_name("CN".to_owned(), domain)
            .set_sign_hash(Type::SHA256)
            .add_extension(Extension::KeyUsage(vec![KeyUsageOption::DigitalSignature]));

        {
            let domain_key = try!(self.domain_key.as_ref().ok_or("Domain key not found"));
            self.domain_csr = Some(try!(generator.request(&domain_key)));
        }

        Ok(self)
    }


    /// Loads CSR from PEM file.
    pub fn load_csr<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let content = {
            let mut file = try!(File::open(path));
            let mut content = Vec::new();
            try!(file.read_to_end(&mut content));
            content
        };
        self.domain_csr = Some(try!(X509Req::from_pem(&content)));
        Ok(self)
    }


    /// Saves CSR file as PEM.
    pub fn save_csr<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        {
            let mut file = try!(File::create(path));
            let csr = try!(self.domain_csr
                           .as_ref()
                           .ok_or("CSR not found"));
            let pem = try!(csr.to_pem());
            try!(file.write_all(&pem));
        }

        Ok(self)
    }



    /// Loads a signed X509 certificate as pem
    ///
    /// This is required if you want to revoke a signed certificate
    pub fn load_certificate<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let content = {
            let mut file = try!(File::open(path));
            let mut content = Vec::new();
            try!(file.read_to_end(&mut content));
            content
        };
        self.signed_cert = Some(try!(X509::from_pem(&content)));
        Ok(self)
    }


    /// Registers new user account.
    ///
    /// You can optionally use an email for this account.
    ///
    /// This function will generate a user key if it's not already generated or loaded from a PEM
    /// file.
    pub fn register_account(mut self, email: Option<&str>) -> Result<Self> {
        if let None = self.user_key {
            self = try!(self.gen_user_key());
        }

        info!("Registering account");

        let mut map = BTreeMap::new();
        map.insert("agreement".to_owned(), self.agreement.to_json());
        if let Some(email) = email {
            map.insert("contract".to_owned(),
            vec![format!("mailto:{}", email)].to_json());
        }
        let (status, resp) = try!(self.request("new-reg", map));
        match status {
            StatusCode::Created => debug!("User successfully registered"),
            StatusCode::Conflict => debug!("User already registered"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        };
        Ok(self)
    }


    /// Makes new identifier authorization request and gets challenges for domain.
    pub fn identify_domain(mut self) -> Result<Self> {
        info!("Sending identifier authorization request");

        let mut map = BTreeMap::new();
        map.insert("identifier".to_owned(), {
            let mut map = BTreeMap::new();
            map.insert("type".to_owned(), "dns".to_owned());
            map.insert("value".to_owned(),
            try!(self.domain
                 .clone()
                 .ok_or("Domain not found. Use domain() to set a domain")));
            map
        });
        let (status, resp) = try!(self.request("new-authz", map));

        if status != StatusCode::Created {
            return Err(ErrorKind::AcmeServerError(resp).into());
        }

        self.challenges = Some(resp.clone());

        for challenge in try!(resp.as_object()
                              .and_then(|obj| obj.get("challenges"))
                              .and_then(|c| c.as_array())
                              .ok_or("No challenge found")) {

            // skip challenges other than http
            // FIXME: http-01 is Let's Encrypt specific
            if !challenge.as_object()
                .and_then(|obj| obj.get("type"))
                    .and_then(|t| t.as_string())
                    .and_then(|t| Some(t == "http-01"))
                    .unwrap_or(false) {
                        continue;
                    }

            let uri = try!(challenge.as_object()
                           .and_then(|obj| obj.get("uri"))
                           .and_then(|t| t.as_string())
                           .ok_or("URI not found in http challange"))
                .to_owned();

            let token = try!(challenge.as_object()
                             .and_then(|obj| obj.get("token"))
                             .and_then(|t| t.as_string())
                             .ok_or("Token not found in http challange"))
                .to_owned();


            let key_authorization =
                format!("{}.{}",
                        token,
                        b64(try!(hash(Type::SHA256, &try!(encode(&try!(self.jwk()))).into_bytes()))));

            self.http_challenge = Some((uri, token, key_authorization));
        }

        Ok(self)
    }


    /// Returns `(uri, token, key_authorization)` from HTTP challenge.
    ///
    /// Get challenges first with `identify_domain()`.
    pub fn get_http_challenge(&self) -> Result<(String, String, String)> {
        let (uri, token, key_authorization) =
            try!(self.http_challenge.clone().ok_or("HTTP challenge not found"));
        Ok((uri, token, key_authorization))
    }


    /// Saves validation token into `{path}/.well-known/acme-challenge/{token}`.
    pub fn save_http_challenge_into<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        let (_, token, key_authorization) = try!(self.get_http_challenge());

        use std::fs::create_dir_all;
        let path = path.as_ref().join(".well-known").join("acme-challenge");
        debug!("Saving validation token into: {:?}", &path);
        try!(create_dir_all(&path));

        let mut file = try!(File::create(path.join(&token)));
        try!(writeln!(&mut file, "{}", key_authorization));

        self.saved_challenge_path = Some(path.join(&token).to_path_buf());

        Ok(self)
    }


    /// Triggers HTTP validation to verify domain ownership.
    pub fn simple_http_validation(self) -> Result<Self> {
        info!("Triggering simple HTTP validation");
        let (uri, _, key_authorization) = try!(self.get_http_challenge());

        let map = {
            let mut map: BTreeMap<String, Json> = BTreeMap::new();
            map.insert("resource".to_owned(), "challenge".to_json());
            map.insert("keyAuthorization".to_owned(), key_authorization.to_json());
            map
        };

        let client = Client::new();
        let mut resp = try!(client.post(&uri)
                            .body(&try!(self.jws(map)))
                            .send());

        let mut res_json: Json = {
            let mut res_content = String::new();
            try!(resp.read_to_string(&mut res_content));
            try!(Json::from_str(&res_content))
        };

        if resp.status != StatusCode::Accepted {
            return Err(ErrorKind::AcmeServerError(res_json).into());
        }

        loop {
            let status = try!(res_json.as_object()
                              .and_then(|o| o.get("status"))
                              .and_then(|s| s.as_string())
                              .ok_or("Status not found"))
                .to_owned();

            if status == "pending" {
                debug!("Status is pending, trying again...");
                let mut resp = try!(client.get(&uri).send());
                res_json = {
                    let mut res_content = String::new();
                    try!(resp.read_to_string(&mut res_content));
                    try!(Json::from_str(&res_content))
                };
            } else if status == "valid" {
                return Ok(self);
            } else if status == "invalid" {
                return Err(ErrorKind::AcmeServerError(res_json).into());
            }

            use std::thread::sleep;
            use std::time::Duration;
            sleep(Duration::from_secs(2));
        }
    }


    /// Signs certificate.
    ///
    /// You need to generate or load a CSR first. Domain also needs to be verified first.
    pub fn sign_certificate(mut self) -> Result<Self> {
        {
            info!("Signing certificate");
            let csr = {
                if let None = self.domain_csr {
                    self = try!(self.gen_csr());
                }
                try!(self.domain_csr.as_ref().ok_or("CSR not found, generate one with gen_csr()"))
            };
            let mut map = BTreeMap::new();
            map.insert("resource".to_owned(), "new-cert".to_owned());
            map.insert("csr".to_owned(), b64(try!(csr.to_der())));

            let client = Client::new();
            let jws = try!(self.jws(map));
            let mut res = try!(client.post(&format!("{}/acme/new-cert", self.ca_server))
                               .body(&jws)
                               .send());

            if res.status != StatusCode::Created {
                let res_json = {
                    let mut res_content = String::new();
                    try!(res.read_to_string(&mut res_content));
                    try!(Json::from_str(&res_content))
                };
                return Err(ErrorKind::AcmeServerError(res_json).into());
            }

            let mut crt_der = Vec::new();
            try!(res.read_to_end(&mut crt_der));

            let b64 = {
                let config = base64::Config {
                    char_set: base64::CharacterSet::Standard,
                    newline: base64::Newline::LF,
                    pad: true,
                    line_length: Some(64),
                };
                format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                        crt_der.to_base64(config))
            };

            self.signed_cert = Some(try!(X509::from_pem(&b64.as_bytes())));
            debug!("Certificate successfully signed")
        }

        Ok(self)
    }


    /// Saves signed certificate as PEM.
    pub fn save_signed_certificate<P: AsRef<Path>>(self, path: P) -> Result<Self> {
        debug!("Saving signed certificate");
        let mut file = try!(File::create(path));
        self.write_signed_certificate(&mut file)
    }


    /// Writes signed certificate to writer
    pub fn write_signed_certificate<W: Write>(self, mut writer: &mut W) -> Result<Self> {
        {
            let crt = try!(self.signed_cert
                           .as_ref()
                           .ok_or("Signed certificate not found, sign certificate \
                        with sigh_certificate() \
                        first"));

            let pem = try!(crt.to_pem());
            try!(writer.write_all(&pem));

            if let Some(url) = self.chain_url.as_ref() {
                let client = Client::new();
                let mut res = try!(client.get(url).send());
                let mut content = String::new();
                try!(res.read_to_string(&mut content));
                try!(write!(&mut writer, "{}", content));
            }
        }

        Ok(self)
    }


    /// Revokes a signed certificate
    ///
    /// You need to load a certificate with load_certificate first
    pub fn revoke_signed_certificate(self) -> Result<Self> {
        let (status, resp) = {
            let crt = try!(self.signed_cert
                           .as_ref()
                           .ok_or("Signed certificate not found, load a signed \
                              certificate with load_certificate() first"));

            let mut map = BTreeMap::new();
            map.insert("certificate".to_owned(), b64(try!(crt.to_der())));

            try!(self.request("revoke-cert", map))
        };

        match status {
            StatusCode::Ok => info!("Certificate successfully revoked"),
            StatusCode::Conflict => warn!("Certificate already revoked"),
            _ => return Err(ErrorKind::AcmeServerError(resp).into()),
        }

        Ok(self)
    }


    /// Makes a new post request, sigs payload and sends signed payload,
    /// returns status code and Json object from reply
    fn request<T: ToJson>(&self, resource: &str, payload: T) -> Result<(StatusCode, Json)> {
        let mut json = payload.to_json();
        json.as_object_mut().and_then(|obj| obj.insert("resource".to_owned(), resource.to_json()));
        let jws = try!(self.jws(json));
        let client = Client::new();
        let mut res = try!(client.post(&format!("{}/acme/{}", self.ca_server, resource))
                           .body(&jws)
                           .send());

        let res_json = {
            let mut res_content = String::new();
            try!(res.read_to_string(&mut res_content));
            if !res_content.is_empty() {
                try!(Json::from_str(&res_content))
            } else {
                true.to_json()
            }
        };

        Ok((res.status, res_json))
    }


    /// Makes a Flattened JSON Web Signature from payload
    fn jws<T: ToJson>(&self, payload: T) -> Result<String> {
        let rsa = try!(try!(self.user_key.as_ref().ok_or("Key not found")).get_rsa());
        let nonce = try!(self.get_nonce());
        let mut data: BTreeMap<String, Json> = BTreeMap::new();

        // header: 'alg': 'RS256', 'jwk': { e, n, kty }
        let mut header: BTreeMap<String, Json> = BTreeMap::new();
        header.insert("alg".to_owned(), "RS256".to_json());
        header.insert("jwk".to_owned(), try!(self.jwk()));
        data.insert("header".to_owned(), header.to_json());

        // payload: b64 of payload
        let payload64 = b64(try!(encode(&payload.to_json())).into_bytes());
        data.insert("payload".to_owned(), payload64.to_json());

        // protected: base64 of header + nonce
        header.insert("nonce".to_owned(), nonce.to_json());
        let protected64 = b64(try!(encode(&header)).into_bytes());
        data.insert("protected".to_owned(), protected64.to_json());

        // signature: b64 of hash of signature of {proctected64}.{payload64}
        data.insert("signature".to_owned(), {
            let hash = try!(hash(Type::SHA256,
                                 &format!("{}.{}", protected64, payload64).into_bytes()));
            b64(try!(rsa.sign(Type::SHA256, &hash))).to_json()
        });

        let json_str = try!(encode(&data));
        Ok(json_str)
    }



    /// Returns jwk field of jws header
    fn jwk(&self) -> Result<Json> {
        let rsa = try!(try!(self.user_key.as_ref().ok_or("Key not found")).get_rsa());
        let mut jwk: BTreeMap<String, String> = BTreeMap::new();
        jwk.insert("e".to_owned(), b64(try!(rsa.e().ok_or("e not found in RSA key")).to_vec()));
        jwk.insert("kty".to_owned(), "RSA".to_owned());
        jwk.insert("n".to_owned(), b64(try!(rsa.n().ok_or("n not found in RSA key")).to_vec()));
        Ok(jwk.to_json())
    }


    fn get_nonce(&self) -> Result<String> {
        let client = Client::new();
        let res = try!(client.get(&format!("{}/directory", self.ca_server)).send());
        res.headers
            .get::<hyperx::ReplayNonce>()
            .ok_or("Replay-Nonce header not found".into())
            .and_then(|nonce| Ok(nonce.as_str().to_string()))
    }
}


impl Drop for AcmeClient {
    fn drop(&mut self) {
        if let Some(path) = self.saved_challenge_path.as_ref() {
            use std::fs::remove_file;
            let _ = remove_file(path);
        }
    }
}


fn gen_key(bit_length: u32) -> Result<PKey> {
    let rsa = try!(RSA::generate(bit_length));
    let key = try!(PKey::from_rsa(rsa));
    Ok(key)
}


fn load_private_key<P: AsRef<Path>>(path: P) -> Result<PKey> {
    let mut file = try!(File::open(path));
    let mut content = Vec::new();
    try!(file.read_to_end(&mut content));
    let key = try!(PKey::private_key_from_pem(&content));
    Ok(key)
}


fn pem_encode_key(key: &PKey, is_public: bool) -> Result<Vec<u8>> {
    let key = try!(key.get_rsa());
    let content = if is_public {
        try!(key.public_key_to_pem())
    } else {
        try!(key.private_key_to_pem())
    };
    Ok(content)
}


fn save_key<P: AsRef<Path>>(key: &PKey, is_public: bool, path: P) -> Result<()> {
    let content = try!(pem_encode_key(key, is_public));
    let mut file = try!(File::create(path));
    try!(file.write_all(&content));
    Ok(())
}


fn b64(data: Vec<u8>) -> String {
    let config = base64::Config {
        char_set: base64::CharacterSet::UrlSafe,
        newline: base64::Newline::LF,
        pad: false,
        line_length: None,
    };
    data.to_base64(config)
}



error_chain! {
    types {
        Error, ErrorKind, ChainErr, Result;
    }

    links {
    }

    foreign_links {
        openssl::error::ErrorStack, OpenSslErrorStack;
        io::Error, IoError;
        hyper::Error, HyperError;
        rustc_serialize::json::EncoderError, JsonEncoderError;
        rustc_serialize::json::ParserError, JsonParserError;
    }

    errors {
        AcmeServerError(resp: Json) {
            description("Acme server error")
                display("Acme server error: {}", acme_server_error_description(resp))
        }
    }
}


fn acme_server_error_description(resp: &Json) -> String {
    if let Some(obj) = resp.as_object() {
        let t = obj.get("type").and_then(|t| t.as_string()).unwrap_or("");
        let detail = obj.get("detail").and_then(|d| d.as_string()).unwrap_or("");
        format!("{} {}", t, detail)
    } else {
        String::new()
    }
}


#[cfg(test)]
/// Tests for AcmeClient
///
/// Ignored tests requires properly setup domain and a working HTTP server to validate domain
/// ownership.
///
/// Ignored tests are using TEST_DOMAIN and TEST_PUBLIC_DIR environment variables.
mod tests {
    extern crate env_logger;
    use super::{AcmeClient, LETSENCRYPT_AGREEMENT};
    use std::collections::BTreeMap;
    use std::env;
    use hyper::status::StatusCode;

    // Use staging API in tests
    const LETSENCRYPT_STAGING_CA_SERVER: &'static str = "https://acme-staging.api.letsencrypt.org";

    #[test]
    fn test_gen_user_key() {
        assert!(AcmeClient::new().and_then(|ac| ac.gen_user_key()).unwrap().user_key.is_some());
    }


    #[test]
    fn test_gen_domain_key() {
        assert!(AcmeClient::new().and_then(|ac| ac.gen_domain_key()).unwrap().domain_key.is_some());
    }


    #[test]
    fn test_gen_csr() {
        assert!(AcmeClient::new()
                .and_then(|ac| ac.set_domain("example.org"))
                .and_then(|ac| ac.gen_csr())
                .unwrap()
                .domain_csr
                .is_some());
    }

    #[test]
    fn test_load_keys_and_csr() {
        assert!(AcmeClient::default().load_user_key("tests/user.key").is_ok());
        assert!(AcmeClient::default().load_domain_key("tests/domain.key").is_ok());
        assert!(AcmeClient::default().load_csr("tests/domain.csr").is_ok());

        assert!(AcmeClient::default().load_user_key("tests/user.key").unwrap().user_key.is_some());
        assert!(AcmeClient::default()
                .load_domain_key("tests/domain.key")
                .unwrap()
                .domain_key
                .is_some());
        assert!(AcmeClient::default().load_csr("tests/domain.csr").unwrap().domain_csr.is_some());
    }

    #[test]
    fn test_get_user_private_key() {
        let res = AcmeClient::default()
            .set_domain("example.org")
            .and_then(|ac| ac.gen_user_key())
            .and_then(|ac| ac.get_user_private_key());

        assert!(res.is_ok());
    }

    #[test]
    fn test_get_user_public_key() {
        let res = AcmeClient::default()
            .set_domain("example.org")
            .and_then(|ac| ac.gen_user_key())
            .and_then(|ac| ac.get_user_public_key());

        assert!(res.is_ok());
    }

    #[test]
    fn test_get_domain_public_key() {
        let res = AcmeClient::default()
            .set_domain("example.org")
            .and_then(|ac| ac.gen_domain_key())
            .and_then(|ac| ac.gen_domain_key())
            .and_then(|ac| ac.get_domain_public_key());

        assert!(res.is_ok());
    }

    #[test]
    fn test_get_domain_private_key() {
        let res = AcmeClient::default()
            .set_domain("example.org")
            .and_then(|ac| ac.gen_domain_key())
            .and_then(|ac| ac.gen_domain_key())
            .and_then(|ac| ac.get_domain_private_key());

        assert!(res.is_ok());
    }

    #[test]
    fn test_save_keys() {
        let res = AcmeClient::default()
            .set_domain("example.org")
            .and_then(|ac| ac.gen_user_key())
            .and_then(|ac| ac.gen_domain_key())
            .and_then(|ac| ac.save_user_private_key("user.key"))
            .and_then(|ac| ac.gen_csr())
            .and_then(|ac| ac.save_user_public_key("user.pub"))
            .and_then(|ac| ac.save_domain_private_key("domain.key"))
            .and_then(|ac| ac.save_domain_public_key("domain.pub"))
            .and_then(|ac| ac.save_csr("domain.csr"));

        assert!(res.is_ok());
    }

    #[test]
    fn test_get_nonce() {
        let ac = AcmeClient::default();
        assert!(ac.get_nonce().is_ok());
    }

    #[test]
    fn test_jws() {
        let ac = AcmeClient::default().gen_user_key().unwrap();
        let mut map = BTreeMap::new();
        map.insert("resource".to_owned(), "new-reg".to_owned());
        map.insert("aggreement".to_owned(), LETSENCRYPT_AGREEMENT.to_owned());
        let jws = ac.jws(map);
        assert!(jws.is_ok());
    }

    #[test]
    fn test_request() {
        let _ = env_logger::init();
        let ac = AcmeClient::new()
            .and_then(|ac| ac.set_ca_server(LETSENCRYPT_STAGING_CA_SERVER))
            .and_then(|ac| ac.gen_user_key()).unwrap();
        let mut map = BTreeMap::new();
        map.insert("aggreement".to_owned(), LETSENCRYPT_AGREEMENT.to_owned());
        let res = ac.request("new-reg", map);
        assert!(res.is_ok());
        let (status, _) = res.unwrap();

        // new user registration must return 201
        assert_eq!(status, StatusCode::Created);
    }

    #[test]
    fn test_register_account() {
        let _ = env_logger::init();
        assert!(AcmeClient::default().set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
                .and_then(|ac| ac.gen_user_key())
                .and_then(|ac| ac.register_account(None))
                .is_ok());
        assert!(AcmeClient::default().set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
                .and_then(|ac| ac.gen_user_key())
                .and_then(|ac| ac.register_account(Some("example@example.org"))).is_ok());
        assert!(AcmeClient::default().set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
                .and_then(|ac| ac.gen_user_key())
                .and_then(|ac| ac.register_account(None))
                .and_then(|ac| ac.register_account(None)) // registration of already register_accounted user
                .is_ok());
    }

    #[test]
    fn test_identify_domain() {
        let _ = env_logger::init();
        assert!(AcmeClient::default().set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
                .and_then(|ac| ac.gen_user_key())
                .and_then(|ac| ac.set_domain("example.org"))
                .and_then(|ac| ac.register_account(None))
                .and_then(|ac| ac.identify_domain())
                .is_ok());
    }

    #[test]
    fn test_get_http_challenge() {
        let _ = env_logger::init();
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.gen_user_key())
            .and_then(|ac| ac.set_domain("example.org"))
            .and_then(|ac| ac.register_account(None))
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.get_http_challenge());
        assert!(ac.is_ok());

        let (uri, token, key_authorization) = ac.unwrap();
        assert!(!uri.is_empty());
        assert!(!token.is_empty());
        assert!(!key_authorization.is_empty());
    }


    #[test]
    fn test_save_http_challenge_into() {
        let _ = env_logger::init();
        assert!(AcmeClient::default()
                .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
                .and_then(|ac| ac.gen_user_key())
                .and_then(|ac| ac.set_domain("example.org"))
                .and_then(|ac| ac.register_account(None))
                .and_then(|ac| ac.identify_domain())
                .and_then(|ac| ac.save_http_challenge_into("test"))
                .is_ok());
        use std::fs::remove_dir_all;
        remove_dir_all("test").unwrap();
    }

    #[ignore]
    #[test]
    fn test_simple_http_validation() {
        let _ = env_logger::init();
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.load_user_key("tests/user.key"))
            .and_then(|ac| ac.set_domain(&env::var("TEST_DOMAIN").unwrap()))
            .and_then(|ac| ac.register_account(None))
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(&env::var("TEST_PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation());

        if let Err(e) = ac.as_ref() {
            error!("{}", e);
        }
        assert!(ac.is_ok());
    }


    #[ignore]
    #[test]
    fn test_sign_certificate() {
        let _ = env_logger::init();
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.load_user_key("tests/user.key"))
            .and_then(|ac| ac.set_domain(&env::var("TEST_DOMAIN").unwrap()))
            .and_then(|ac| ac.register_account(None))
            .and_then(|ac| ac.gen_csr())
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(&env::var("TEST_PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation())
            .and_then(|ac| ac.sign_certificate());

        if let Err(e) = ac.as_ref() {
            error!("{}", e);
        }
        assert!(ac.is_ok());
    }


    #[ignore]
    #[test]
    fn test_save_certificate_into() {
        let _ = env_logger::init();
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.load_user_key("tests/user.key"))
            .and_then(|ac| ac.set_domain(&env::var("TEST_DOMAIN").unwrap()))
            .and_then(|ac| ac.register_account(None))
            .and_then(|ac| ac.gen_csr())
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(&env::var("TEST_PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation())
            .and_then(|ac| ac.sign_certificate())
            .and_then(|ac| ac.save_signed_certificate("domain.crt"));

        if let Err(e) = ac.as_ref() {
            error!("{}", e);
        }
        assert!(ac.is_ok());
    }

    #[test]
    #[ignore]
    fn test_revoke_signed_certificate() {
        let _ = env_logger::init();
        // sign a certificate first
        debug!("Signing a certificate");
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.load_user_key("tests/user.key"))
            .and_then(|ac| ac.set_domain(&env::var("TEST_DOMAIN").unwrap()))
            .and_then(|ac| ac.register_account(None))
            .and_then(|ac| ac.gen_csr())
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(&env::var("TEST_PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation())
            .and_then(|ac| ac.sign_certificate())
            .and_then(|ac| ac.save_signed_certificate("domain.crt"));
        if let Err(e) = ac.as_ref() {
            error!("{}", e);
        }
        assert!(ac.is_ok());

        // try to revoke signed certificate
        debug!("Trying to revoke signed certificate");
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.load_user_key("tests/user.key"))
            .and_then(|ac| ac.load_certificate("domain.crt"))
            .and_then(|ac| ac.revoke_signed_certificate());

        if let Err(e) = ac.as_ref() {
            error!("{}", e);
        }
        assert!(ac.is_ok());
    }

    #[test]
    #[ignore]
    fn test_chain() {
        let _ = env_logger::init();
        let ac = AcmeClient::default()
            .set_ca_server(LETSENCRYPT_STAGING_CA_SERVER)
            .and_then(|ac| ac.load_user_key("tests/user.key"))
            .and_then(|ac| ac.set_domain(&env::var("TEST_DOMAIN").unwrap()))
            .and_then(|ac| ac.set_chain_url("https://letsencrypt.org/certs/\
                                            lets-encrypt-x3-cross-signed.pem"))
            .and_then(|ac| ac.register_account(Some("onur@onur.im")))
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(&env::var("TEST_PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation())
            .and_then(|ac| ac.sign_certificate())
            .and_then(|ac| ac.save_domain_private_key("domain.key"))
            .and_then(|ac| ac.save_signed_certificate("domain.crt"));

        if let Err(e) = ac.as_ref() {
            error!("{}", e);
        }
        assert!(ac.is_ok());
    }
}
