// Define a struct and implement functions on it for making various API calls
// to the Venafi TPP.
extern crate serde;
extern crate serde_json;
use hyper::Client;
use hyper::net::HttpsConnector;
use hyper_native_tls::NativeTlsClient;
use hyper::client::Response;
use hyper::header::*;
use serde_json::Value;
use types::*;
use std::collections::HashMap;
use std::io::Read;
use base64::decode;
use utils;
use openssl::pkcs12::Pkcs12;
use time;

#[derive(Debug)]
pub struct VenafiAPI {
    username: String,
    password: String,
    hostname: String,
    apikey: String,
    pub cadns: HashMap<String, String>,
    pub folders: HashMap<String, String>
}

impl VenafiAPI {
    pub fn new(u: &str, p: &str, h: &str) -> VenafiAPI {
        VenafiAPI { username: u.to_string(),
                    password: p.to_string(),
                    hostname: h.to_string(),
                    apikey: String::new(),
                    cadns: HashMap::new(),
                    folders: HashMap::new() }
    }

    // Define our own reusable GET/POST functions
    pub fn get(&self, uri: &str) -> Response {
        let ssl = NativeTlsClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);
        let full_uri = self.hostname.clone() + uri;
        let headers = self.set_headers();
        client.get(&full_uri).headers(headers).send().unwrap()
    }

    pub fn post<'a, T>(&self, uri: &str, payload: &T) -> Response where T: serde::Serialize {
        let body = serde_json::to_string(&payload).unwrap();
        let ssl = NativeTlsClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);
        let full_uri = self.hostname.clone() + uri;
        let headers = self.set_headers();
        client.post(&full_uri).body(&body).headers(headers).send().unwrap()
    }

    // Automatically set the content type header and the Venafi API Key header
    pub fn set_headers(&self) -> Headers {
        let mut headers = Headers::new();
        headers.set(ContentType::json());
        headers.set_raw("X-Venafi-Api-Key", vec!(self.apikey.clone().into_bytes()));
        headers
    }

    // Call /Authorize/ and obtain an API key
    // This is the only REST call that won't use self.post()
    pub fn authenticate(&mut self) -> bool {
        let mut payload = HashMap::new();
        payload.insert("Username", self.username.as_str());
        payload.insert("Password", self.password.as_str());
        let body = serde_json::to_string(&payload).unwrap();
        let uri = self.hostname.clone() + "/Authorize/";
        let ssl = NativeTlsClient::new().unwrap();
        let connector = HttpsConnector::new(ssl);
        let client = Client::with_connector(connector);
        //let client = Client::new();
        let mut headers = Headers::new();
        headers.set(ContentType::json());
        match client.post(&uri).body(&body).headers(headers).send() {
            Ok(mut res) => {
                let mut body = String::new();
                res.read_to_string(&mut body).expect("Error reading response");
                let parsed: Value = serde_json::from_str(body.as_str()).expect("Can't parse response");
                let key: String = parsed["APIKey"].as_str().unwrap().to_string();
                self.apikey = key;
                true
            }
            Err(e) => {
                println!("Error authenticating: {}", e);
                false
            }
        }
    }

    // Retrieve metadata for X509 Server Certificate objects available to the
    // authenticated user
    pub fn fetch_cert_metadata(&self) -> HashMap<String, String> {
        // FindObjectsOfClass X509 Server Certificate
        // Recursive = 1
        // Process the returned JSON into an FOOC
        // Iterate through FOOC.objects vector
        // Grab DN and Name attributes, stick in HashMap
        // return hashmap
        let mut payload = HashMap::new();
        payload.insert("Class", "X509 Server Certificate");
        payload.insert("Recursive", "1");
        let mut result = self.post("/Config/FindObjectsOfClass", &payload);
        // Result should be able to be turned into a FOOC struct
        // Sanity check the result and return an empty HashMap on error
        if !self.validate_result(&mut result) {
            return HashMap::new()
        }
        let mut body = String::new();
        result.read_to_string(&mut body).expect("Error reading response");
        let parsed: FOOC = serde_json::from_str(&body).expect("Error converting JSON");
        let mut retval = HashMap::new();
        for x in &parsed.objects {
            retval.insert(x.dn.clone(), x.name.clone());
        }
        retval
    }

    // Attempt to retrieve a PKCS#12 certificate with random password.
    pub fn fetch_certificate(&self, dn: &str) -> P12Bundle {
        // Generate password string
        let pass = utils::generate_pass();
        // Construct payload: CertificateDN, Format, IncludeChain,
        // IncludePrivateKey, Password.
        let mut payload = HashMap::new();
        payload.insert("CertificateDN", dn);
        payload.insert("Format", "PKCS #12");
        payload.insert("IncludeChain", "1");
        payload.insert("IncludePrivateKey", "1");
        payload.insert("Password", &pass);
        // Post to /certificates/Retrieve
        let mut result = self.post("/certificates/Retrieve", &payload);
        if !self.validate_result(&mut result) {
            panic!("Certificate cannot be retrieved");
        }
        let mut body = String::new();
        result.read_to_string(&mut body).expect("Error reading response");
        let parsed: RetrievedCert = serde_json::from_str(&body).expect("Error converting JSON");
        // Parse out RetrievedCert struct and data attribute
        // Base64 decode it?
        let decoded = decode(&parsed.data).expect("Unable to base64 decode");
        let pk12 = Pkcs12::from_der(&decoded).expect("Bad p12?");
        let retval = P12Bundle { p12: pk12, pwd: pass.clone() };
        retval
    }

    // Fetch the cert and extract the 'not_after' attribute.  Need to look
    // up how to manipulate OpenSSL structs.
    pub fn fetch_expiry(&self, dn: &str) -> i64 {
        // Grab the cert/pass using fetch_certificate
        let certdata = self.fetch_certificate(dn);
        let parsed = certdata.p12.parse(&certdata.pwd).expect("Bad password?");
        let notafter: String = format!("{}", &parsed.cert.not_after());
        let t = time::strptime(&notafter, "%b %d %T %Y %Z").expect("Invalid time format");
        let diff = t - time::now();
        diff.num_days()
    }

    // Request a new certificate.  Takes a subject, san list (can be empty),
    // name of a certificate authority, and name of a folder/policydn
    pub fn request_certificate(&self, sub: &str, san: &[String], ca: &str, f: &str) -> bool {
        // Sanity check CA and folder names
        if !self.cadns.contains_key(ca) {
            println!("No CA DN found for CA name {}", ca);
            return false
        }
        if !self.folders.contains_key(f) {
            println!("No policy DN found for folder name {}", f);
            return false
        }
        // Prep CASpecificAttributes hashmap
        let csa: HashMap<String, String> = 
            [("Name".to_string(), "Validity Period".to_string()),
             ("Value".to_string(), "365".to_string())]
            .iter().cloned().collect();
        let mut csav = Vec::new();
        csav.push(csa);

        // Create a CertificateRequest struct with our available data
        let mut payload = CertificateRequest {
            policydn:   self.folders.get(f).unwrap().to_owned(),
            cadn:       self.cadns.get(ca).unwrap().to_owned(),
            specific:   csav,
            subject:    Some(sub.to_string()),
            objectname: None,
            pkcs10:     None,
            san:        None,
        };
        let mut sans = Vec::new();
        for s in san {
            let typename: HashMap<String, String> =
                [("Type".to_string(), "2".to_string()),
                 ("Name".to_string(), s.to_string())]
                .iter().cloned().collect();
            sans.push(typename);
        }
        // Stuff into payload if needed
        if sans.len() > 1 {
            payload.san = Some(sans);
        }

        let mut result = self.post("/Certificates/Request", &payload);
        if self.validate_result(&mut result) {
            println!("Successfully requested {}", sub);
            true
        } else {
            false
        }
    }

    // Do a request but with a CSR instead of subj/san.  Takes a name, csr,
    // cert authority, and folder name
    pub fn request_with_csr(&self, name: &str, csr: &str, ca: &str, f: &str) -> bool {
        // Sanity check CA and folder names
        if !self.cadns.contains_key(ca) {
            println!("No CA DN found for CA name {}", ca);
            return false
        }
        if !self.folders.contains_key(f) {
            println!("No policy DN found for folder name {}", f);
            return false
        }
        // Prep CASpecificAttributes hashmap
        let csa: HashMap<String, String> =
            [("Name".to_string(), "Validity Period".to_string()),
             ("Value".to_string(), "365".to_string())]
            .iter().cloned().collect();
        let mut csav = Vec::new();
        csav.push(csa);

        // Create a CertificateRequest struct with available data
        let payload = CertificateRequest {
            policydn:   self.folders.get(f).unwrap().to_owned(),
            cadn:       self.cadns.get(ca).unwrap().to_owned(),
            specific:   csav,
            subject:    None,
            objectname: Some(name.to_string()),
            pkcs10:     Some(csr.to_string()),
            san:        None
        };
        let mut result = self.post("/Certificates/Request", &payload);
        if self.validate_result(&mut result) {
            println!("Successfully requested {}", name);
            true
        } else {
            false
        }
    }

    // Send a renewal request given the DN of a certificate
    pub fn renew_certificate(&self, dn: &str) -> bool {
        let mut payload = HashMap::new();
        payload.insert("CertificateDN", &dn);
        let mut result = self.post("/Certificates/Renew", &payload);
        if self.validate_result(&mut result) {
            println!("Successfully submitted renewal request for {}", dn);
            true
        } else {
            false
        }
    }

    // Send a revoke request given the DN of a certificate
    pub fn revoke_certificate(&self, dn: &str) -> bool {
        let mut payload = HashMap::new();
        payload.insert("CertificateDN", dn);
        payload.insert("Reason", "5");
        payload.insert("Comments", "Revoked via API");
        let mut result = self.post("/Certificates/Revoke", &payload);
        if self.validate_result(&mut result) {
            println!("Successfully submitted revoke request for {}", dn);
            true
        } else {
            return false
        }
    }

    // Determine the revocation status of a certificate. Takes cert DN.
    pub fn check_revoked(&self, dn: &str) -> bool {
        // Two step process:
        // 1. Obtain vaultID via /Config/Read
        // 2. Obtain cert metadata via /X509CertificateStore/Retrieve
        // If the array TypedNameValues contains a hash with the name
        // 'Revocation Status' and a non-null value, certificate is revoked.
        let mut payload = HashMap::new();
        payload.insert("ObjectDN", dn);
        payload.insert("AttributeName", "Certificate Vault Id");
        let mut result = self.post("/Config/Read", &payload);
        if !self.validate_result(&mut result) {
            return false
        }
        let mut body = String::new();
        result.read_to_string(&mut body).expect("Error reading response");
        let mut parsed: ConfigRead = serde_json::from_str(&body).expect("Error converting JSON");
        let vault_id = parsed.values.pop().unwrap();

        let mut p2 = HashMap::new();
        p2.insert("VaultId", vault_id.as_str());
        result = self.post("/X509CertificateStore/Retreive", &p2);
        if !self.validate_result(&mut result) {
            return false
        }
        body = String::new();
        result.read_to_string(&mut body).expect("Error reading response");
        let daters: X509CertStore = serde_json::from_str(&body).expect("Error converting JSON");
        for t in &daters.typednamevalues {
            if t.name == "Revocation Status" && !t.value.is_empty() {
                return true
            }
        }
        false
    }

    // This code kept getting repeated so lets factor it out to its own fn.
    fn validate_result(&self, res: &mut Response) -> bool {
        // Return true if status is successful, print error and return false
        // otherwise.
        if res.status.is_success() {
            true
        } else {
            let stat = res.status;
            let mut why = String::new();
            res.read_to_string(&mut why).expect("Can't read response?");
            println!("Received error {}: {:?}", stat, why);
            false
        }
    }
}
