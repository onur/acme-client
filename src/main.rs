/// Easy to use Let's Encrypt client to issue and renew TLS certs

extern crate acme_client;
extern crate clap;
extern crate env_logger;


use acme_client::AcmeClient;
use clap::{Arg, App};


fn main() {
    let _ = env_logger::init();
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("USER_KEY_PATH")
            .help("User private key path to use it in account registration.")
            .long("user-key")
            .takes_value(true))
        .arg(Arg::with_name("DOMAIN_KEY_PATH")
            .help("Domain private key path to use it in CSR generation.")
            .long("domain-key")
            .takes_value(true))
        .arg(Arg::with_name("DOMAIN")
            .help("Name of domain for identification.")
            .short("D")
            .long("domain")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("PUBLIC_DIR")
            .help("Directory to save ACME simple http challenge.")
            .short("P")
            .long("public-dir")
            .required(true)
            .takes_value(true))
        .arg(Arg::with_name("EMAIL")
            .help("Contact email address (optional).")
            .short("E")
            .long("email")
            .takes_value(true))
        .arg(Arg::with_name("DOMAIN_CSR")
            .help("Path of domain certificate signing request.")
            .short("C")
            .long("domain-csr")
            .takes_value(true))
        .arg(Arg::with_name("SAVE_USER_KEY")
            .help("Path to save private user key.")
            .short("U")
            .long("save-user-key")
            .takes_value(true))
        .arg(Arg::with_name("SAVE_DOMAIN_KEY")
            .help("Path to save domain private key.")
            .short("K")
            .long("save-domain-key")
            .takes_value(true))
        .arg(Arg::with_name("SAVE_DOMAIN_CSR")
            .help("Path to save domain certificate signing request.")
            .long("save-csr")
            .takes_value(true))
        .arg(Arg::with_name("SAVE_SIGNED_CERTIFICATE")
            .help("Path to save signed certificate. Default is STDOUT.")
            .short("o")
            .long("save-crt")
            .takes_value(true))
        .arg(Arg::with_name("BIT_LENGHT")
            .help("Set bit length for CSR. Default is 2048.")
            .long("bit-length")
            .takes_value(true))
        .arg(Arg::with_name("CHAIN")
            .help("Chains the signed certificate with Let's Encrypt Authority X3 (IdenTrust \
                   cross-signed) intermediate certificate.")
            .short("c")
            .long("chain")
            .takes_value(false))
        .get_matches();


    let mut ac = AcmeClient::new();

    if let Some(csr_path) = matches.value_of("DOMAIN_CSR") {
        ac = ac.load_csr(csr_path).expect("Failed to load CSR");
    }

    if let Some(domain) = matches.value_of("DOMAIN") {
        ac = ac.set_domain(domain);
    }

    if matches.is_present("CHAIN") {
        ac = ac.set_chain_url("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem");
    }

    if let Some(bit_length) = matches.value_of("BIT_LENGTH") {
        ac = ac.set_bit_length(bit_length.parse().expect("Bit length must be a number"))
            .expect("Failed to set bit lenght");
    }

    if let Some(user_key_path) = matches.value_of("USER_KEY_PATH") {
        ac = ac.load_user_key(user_key_path).expect("Failed to load user key");
    }

    if let Some(domain_key_path) = matches.value_of("DOMAIN_KEY_PATH") {
        ac = ac.load_domain_key(domain_key_path).expect("Failed to load domain key");
    }

    ac = ac.register_account(matches.value_of("EMAIL"))
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(matches.value_of("PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation())  // unwrap is fine here ~~~~^
            .and_then(|ac| ac.sign_certificate())        // PUBLIC_DIR is always required
            .expect("Failed to sign certificate");

    if let Some(path) = matches.value_of("SAVE_USER_KEY") {
        ac = ac.save_user_private_key(path).expect("Failed to save user private key");
    }

    if let Some(path) = matches.value_of("SAVE_DOMAIN_KEY") {
        ac = ac.save_domain_private_key(path).expect("Failed to save domain private key");
    }

    if let Some(path) = matches.value_of("SAVE_SIGNED_CERTIFICATE") {
        ac.save_signed_certificate(path).expect("Failed to save signed certificate");
    } else {
        use std::io::stdout;
        ac.write_signed_certificate(&mut stdout()).expect("Failed to write signed certificate");
    }
}
