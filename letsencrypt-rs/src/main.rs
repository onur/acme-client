/// Easy to use Let's Encrypt client to issue and renew TLS certs

extern crate acme_client;
extern crate clap;
extern crate env_logger;


use std::io::{self, Write};
use acme_client::Directory;
use acme_client::error::Result;
use clap::{Arg, App, SubCommand, ArgMatches};


fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .usage("letsencrypt-rs sign -D example.org -P /var/www -k domain.key -o domain.crt\
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
                .help("Names of domain for identification. You can use more than one domain name.")
                .short("D")
                .long("domain")
                .multiple(true)
                .required(true)
                .takes_value(true))
            .arg(Arg::with_name("PUBLIC_DIR")
                .help("Directory to save ACME simple http challenge. This option is required.")
                .short("P")
                .long("public-dir")
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
            .arg(Arg::with_name("CHAIN")
                .help("Chains the signed certificate with Let's Encrypt Authority X3 \
                       (IdenTrust cross-signed) intermediate certificate.")
                .short("c")
                .long("chain")
                .takes_value(false))
            .arg(Arg::with_name("DNS_CHALLENGE")
                 .help("Use DNS challenge instead of HTTP. This option requires user \
                        to generate a TXT record for domain")
                 .short("d")
                 .long("dns")
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
        .arg(Arg::with_name("verbose")
             .help("Show verbose output")
             .short("v")
             .multiple(true))
        .get_matches();

    init_logger(matches.occurrences_of("verbose"));

    let res = if let Some(matches) = matches.subcommand_matches("sign") {
        // TODO: remove unwrap
        sign_certificate(matches)
    } else if let Some(matches) = matches.subcommand_matches("revoke") {
        revoke_certificate(matches)
    } else {
        Err(matches.usage().into())
    };

    if let Err(e) = res {
        writeln!(io::stderr(), "{}", e).expect("Failed to write stderr");
    }
}



fn sign_certificate(matches: &ArgMatches) -> Result<()> {
    let directory = Directory::lets_encrypt()?;

    let mut account_registration = directory.account_registration();

    if let Some(email) = matches.value_of("EMAIL") {
        account_registration = account_registration.email(email);
    }

    if let Some(user_key_path) = matches.value_of("USER_KEY_PATH") {
        account_registration = account_registration.pkey_from_file(user_key_path)?;
    }

    let account = account_registration.register()?;
    let domains: Vec<_> = matches.values_of("DOMAIN")
        .ok_or("You need to provide at least one domain name")?
        .collect();
    for domain in &domains {
        let authorization = account.authorization(domain)?;
        if !matches.is_present("DNS_CHALLENGE") {
            let challenge = authorization.get_http_challenge().ok_or("HTTP challenge not found")?;
            challenge.save_key_authorization(matches.value_of("PUBLIC_DIR")
                                                 .ok_or("--public-dir not defined. \
                                                            You need to define a public \
                                                            directory to use http challenge \
                                                            verification")?)?;
            challenge.validate()?;
        } else {
            let challenge = authorization.get_dns_challenge().ok_or("DNS challenge not found")?;
            println!("Please create a TXT record for _acme-challenge.{}: {}\n\
                      Press enter to continue",
                     domain,
                     challenge.signature()?);
            io::stdin().read_line(&mut String::new()).unwrap();
            challenge.validate()?;
        }
    }

    let mut certificate_signer = account.certificate_signer(&domains);

    if let Some(domain_key_path) = matches.value_of("DOMAIN_KEY_PATH") {
        if let Some(csr_path) = matches.value_of("DOMAIN_CSR") {
            certificate_signer = certificate_signer.csr_from_file(domain_key_path, csr_path)?;
        } else {
            certificate_signer = certificate_signer.pkey_from_file(domain_key_path)?;
        }
    }

    let certificate = certificate_signer.sign_certificate()?;
    let signed_certificate_path = matches.value_of("SAVE_SIGNED_CERTIFICATE")
        .ok_or("You need to save signed certificate")?;
    if matches.is_present("CHAIN") {
        certificate.save_signed_certificate_and_chain(None, signed_certificate_path)?;
    } else {
        certificate.save_signed_certificate(signed_certificate_path)?;
    }

    if let Some(path) = matches.value_of("SAVE_DOMAIN_KEY") {
        certificate.save_private_key(path)?;
    }
    if let Some(path) = matches.value_of("SAVE_DOMAIN_CSR") {
        certificate.save_csr(path)?;
    }
    if let Some(path) = matches.value_of("SAVE_USER_KEY") {
        account.save_private_key(path)?;
    }

    Ok(())
}


fn revoke_certificate(matches: &ArgMatches) -> Result<()> {
    let directory = Directory::lets_encrypt()?;
    let account = directory.account_registration()
        .pkey_from_file(matches.value_of("USER_KEY_PATH")
                            .ok_or("You need to provide user \
                                   or domain private key used \
                                   to sign certificate.")?)?
        .register()?;
    account.revoke_certificate_from_file(matches.value_of("SIGNED_CRT")
                                             .ok_or("You need to provide \
                                                    a signed certificate to \
                                                    revoke.")?)?;
    Ok(())
}


fn init_logger(level: u64) {
    let level = match level {
        0 => "",
        1 => "acme_client=info",
        _ => "acme_client=debug",
    };
    let mut builder = env_logger::LogBuilder::new();
    builder.parse(&::std::env::var("RUST_LOG").unwrap_or(level.to_owned()));
    let _ = builder.init();
}
