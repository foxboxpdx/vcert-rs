# vcert-rs
Rust implementation of the Venafi 'VCert' API

## Rough Usage

### Instantiate a VenafiAPI struct
- Supply an Auth struct containing username, password, and base url/hostname
- Supply a Config struct containing folder DNs and cert authority DNs
-  - Suggest supplying the former via ENV keys, latter via JSON file

### Authenticate with your Venafi instance

```rust
let foo = VenafiAPI::new(authdata, configdata);
match foo.get_api_key() {
    Ok() => { // success },
    Err(e) => { // reqwest::Error struct }
}
```

### Populate a HashMap of Certificate Metadata

```rust
let metadata = match foo.fetch_cert_metadata() {
    Ok(bar) => { // 'bar' is a HashMap of String, String },
    Err(e) => { // reqwest::Error }
};
```

### Retrieve a Certificate
```rust
let certdn = // do some hashmap thing to get the dn-to-cn mapping
// Takes a DN, desired format (ie pem), include chain (bool), include private key (bool)
let (cert, pass) = match foo.fetch_certificate(certdn, "pem", true, true) {
    Ok((x,y)) => { // x is cert, y is password if pkey included },
    Err((z, zz)) => { // z is an i32 http code, zz is an error message }
};
```

## Other supported Actions

- Check expiration of a cert
- Request with a commonName string and SAN Vec
- Request with a CSR
- Renew existing cert
- Revoke existing cert
- Check if a cert has already been revoked


Better docs coming eventually.  Stay tuned for a pair of front-ends to this crate once it's finished and tested - vcert-rs-cli and vcert-rs-gui

