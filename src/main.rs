/// Easy to use Let's Encrypt client to issue and renew TLS certs

extern crate acme_client;
extern crate clap;
extern crate env_logger;


use acme_client::AcmeClient;
use clap::{Arg, App, SubCommand};


fn main() {
    let _ = env_logger::init();
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .usage("letsencrypt-rs sign -D example.org -P /var/www -K domain.key -o domain.crt\
                \n    letsencrypt-rs revoke -K user_or_domain.key -C signed.crt")
        .subcommand(SubCommand::with_name("sign")
            .about("Signs a certificate")
            .display_order(1)
            .arg(Arg::with_name("USER_KEY_PATH")
                .help("User private key path to use it in account registration.")
                .long("user-key")
                .short("U")
                .takes_value(true))
            .arg(Arg::with_name("DOMAIN_KEY_PATH")
                .help("Domain private key path to use it in CSR generation.")
                .short("K")
                .long("domain-key")
                .takes_value(true))
            .arg(Arg::with_name("DOMAIN")
                .help("Name of domain for identification. This option is required.")
                .short("D")
                .long("domain")
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("PUBLIC_DIR")
                .help("Directory to save ACME simple http challenge. This option is required.")
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
                .help("Path to domain certificate signing request.")
                .short("C")
                .long("domain-csr")
                .takes_value(true))
            .arg(Arg::with_name("SAVE_USER_KEY")
                .help("Path to save private user key.")
                .long("save-user-key")
                .short("u")
                .takes_value(true))
            .arg(Arg::with_name("SAVE_DOMAIN_KEY")
                .help("Path to save domain private key.")
                .short("k")
                .long("save-domain-key")
                .takes_value(true))
            .arg(Arg::with_name("SAVE_DOMAIN_CSR")
                .help("Path to save domain certificate signing request.")
                .long("save-csr")
                .short("S")
                .takes_value(true))
            .arg(Arg::with_name("SAVE_SIGNED_CERTIFICATE")
                .help("Path to save signed certificate. Default is STDOUT.")
                .short("o")
                .long("save-crt")
                .takes_value(true))
            .arg(Arg::with_name("BIT_LENGHT")
                .help("Bit length for CSR. Default is 2048.")
                .long("bit-length")
                .short("B")
                .takes_value(true))
            .arg(Arg::with_name("CHAIN")
                .help("Chains the signed certificate with Let's Encrypt Authority X3 \
                       (IdenTrust cross-signed) intermediate certificate.")
                .short("c")
                .long("chain")
                .takes_value(false)))
        .subcommand(SubCommand::with_name("revoke")
            .about("Revokes a signed certificate")
            .display_order(2)
            .arg(Arg::with_name("USER_KEY")
                .help("User or domain private key path.")
                .long("user-key")
                .short("K")
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("SIGNED_CRT")
                .help("Path to signed domain certificate to revoke.")
                .long("signed-crt")
                .short("C")
                .required(true)
                .takes_value(true)))
        .get_matches();


    let mut ac = AcmeClient::new().expect("Failed to create new AcmeClient");


    // sign certificate
    if let Some(matches) = matches.subcommand_matches("sign") {

        if let Some(csr_path) = matches.value_of("DOMAIN_CSR") {
            ac = ac.load_csr(csr_path).expect("Failed to load CSR");
        }

        if let Some(domain) = matches.value_of("DOMAIN") {
            ac = ac.set_domain(domain).expect("Failed to set domain")
        }

        if matches.is_present("CHAIN") {
            ac = ac.set_chain_url("https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem")
                .expect("Failed to set chain URL")
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

        if let Some(domain_crt_path) = matches.value_of("DOMAIN_CRT") {
            ac = ac.load_certificate(domain_crt_path)
                .expect("Failed to load signed domain certificate");
        }

        ac = ac.register_account(matches.value_of("EMAIL"))
            .and_then(|ac| ac.identify_domain())
            .and_then(|ac| ac.save_http_challenge_into(matches.value_of("PUBLIC_DIR").unwrap()))
            .and_then(|ac| ac.simple_http_validation())  // unwrap is fine here ~~~~^
            .and_then(|ac| ac.sign_certificate())        // PUBLIC_DIR is always required
            .expect("Failed to sign certificate");

        if let Some(path) = matches.value_of("SAVE_SIGNED_CERTIFICATE") {
            ac = ac.save_signed_certificate(path).expect("Failed to save signed certificate");
        } else {
            use std::io::stdout;
            ac = ac.write_signed_certificate(&mut stdout())
                .expect("Failed to write signed certificate");
        }

        if let Some(path) = matches.value_of("SAVE_USER_KEY") {
            ac = ac.save_user_private_key(path).expect("Failed to save user private key");
        }

        if let Some(path) = matches.value_of("SAVE_DOMAIN_KEY") {
            ac.save_domain_private_key(path).expect("Failed to save domain private key");
        }
    }
    // revoke certificate
    else if let Some(matches) = matches.subcommand_matches("revoke") {
        ac = ac.load_user_key(matches.value_of("USER_KEY").unwrap())
            .expect("Failed to load user key");
        ac = ac.load_certificate(matches.value_of("SIGNED_CRT").unwrap())
            .expect("Failed to load signed domain certificate");
        ac.revoke_signed_certificate().expect("Failed to revoke certificate");
        println!("Certificate successfully revoked!");
    }
    // if none of them matches, show usage
    else {
        println!("{}", matches.usage());
    }
}
