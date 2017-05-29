// Testing
extern crate zerda;
extern crate serde;
extern crate serde_json;

use zerda::api::VenafiAPI;
use zerda::types::*;
use std::io::Read;
use std::io::Write;
use std::fs::File;
use std::env;

fn main() {
    let user = env::var("VENUSER").unwrap();
    let pass = env::var("VENPASS").unwrap();
    let host = env::var("VENHOST").unwrap();
    let mut api = VenafiAPI::new(&user, &pass, &host);

    // Read the config
    let mut config = String::new();
    let mut f = File::open("config.json").expect("Unable to read config");
    f.read_to_string(&mut config).expect("Unable to read file");
    let settings: ZerdaConfig = serde_json::from_str(&config)
        .expect("Error parsing JSON");
    api.cadns = settings.certauthorities;
    api.folders = settings.folders;

    api.authenticate();

    // Test fetch_cert_metadata
    let meta = api.fetch_cert_metadata();

    let certdn = "\\VED\\Policy\\Certificates\\foo.com";

    // Test fetch_certificate
    let certnpass = api.fetch_certificate(&certdn);
    let mut certfile = File::create("cert.p12").expect("Unable to open cert out");
    certfile.write_all(certnpass.p12.to_der().unwrap().as_slice())
        .expect("Unable to write cert");
    let mut passfile = File::create("cert.pwd").expect("Unable to open pass out");
    passfile.write_all(certnpass.pwd.as_bytes()).expect("Unable to write pass");

    // Test fetch_expiry
    let daysleft = api.fetch_expiry(&certdn);
    println!("Certificate {} expires in {} days", certdn, daysleft);
}
