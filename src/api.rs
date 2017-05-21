// Define a struct and implement functions on it for making various API calls
// to the Venafi TPP.
use hyper::Client;
use hyper::client::Response;
use hyper::header::*;
use hyper::mime::Mime;
use serde_json::Value;
use types::*;
use std::collections::HashMap;

pub struct VenafiAPI {
    username: String,
    password: String,
    hostname: String,
    apikey: String,
    cadns: HashMap<String, String>,
    folders: HashMap<String, String>
}

impl VenafiAPI {
    pub fn new(u: &str, p: &str, h: &str) -> VenafiAPI {
        VenafiAPI { username: u.to_string().
                    password: p.to_string(),
                    hostname: h.to_string(),
                    apikey: "",
                    cadns: HashMap::new(),
                    folders: HashMap::new() }
    }

    // Define our own reusable GET/POST functions
    pub fn get(&self, uri: &str) -> Response {
        let client = Client::new();
        let full_uri = self.hostname.clone() + uri;
        let headers = self.set_headers();
        client.get(&full_uri).headers(headers).send().unwrap()
    }

    pub fn post<'a, T>(&self, uri: &str, payload: &T) -> Response where T: serde::Serialize {
        let body = serde_json::to_string(&payload).unwrap();
        let client = Client::new();
        let full_uri = self.hostname.clone() + uri;
        let headers = self.set_headers();
        client.post(&full_uri).body(&body).headers(headers).send().unwrap()
    }

    // Automatically set the content type header and the Venafi API Key header
    pub fn set_headers(&self) -> Headers {
        let mut headers = Headers::new();
        headers.set(ContentType::json());
        headers.set_raw("X-Venafi-Api-Key", self.apikey.as_str());
        headers
    }

    // Call /Authorize/ and obtain an API key
    // This is the only REST call that won't use self.post()
    pub fn authenticate(&self) -> bool {
        let mut payload = HashMap::new();
        payload.insert("Username", self.username.as_str());
        payload.insert("Password", self.password.as_str());
        let body = serde_json::to_string(&payload).unwrap();
        let uri = self.hostname.clone() + "/Authorize/";
        let client = Client::new();
        let mut headers = Headers::new();
        headers.set(ContentType::json());
        match client.post(&uri).body(&body).headers(headers).send() {
            Ok(res) => {
                let mut body = String::new();
                res.read_to_string(&mut body).expect("Error reading response");
                let parsed: Value = serde_json::from_str(body.as_str()).expect("Can't parse response");
                self.apikey = parsed["APIKey"];
                true
            }
            Err(e) => {
                println!("Error authenticating: {}", e);
                false
            }
        }
    }

    // Need to figure out some better way of doing this - maybe folder should 
    // be static, defined in a conf file of some sort with the CADNs?
    pub fn find_folders(&self) -> bool {
        true
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
        let mut retval = HashMap::new();
        retval
    }

    // Attempt to retrieve a PKCS#12 certificate with random password.
    pub fn fetch_certificate(&self, dn: &str) -> Vec<&str> {
        // Generate password string
        // Construct payload: CertificateDN, Format, IncludeChain,
        // IncludePrivateKey, Password.
        // Post to /certificates/Retrieve
        // Parse out RetrievedCert struct and data attribute
        // Base64 decode it?
        // Return a vector of the cert string and password string
        let mut retval = Vec::new();
        retval
    }

    // Fetch the cert and extract the 'not_after' attribute.  Need to look
    // up how to manipulate OpenSSL structs.
    pub fn fetch_expiry(&self, dn: &str) -> bool {
        true
    }

    // Request a new certificate.  Takes a subject, san list (can be empty),
    // name of a certificate authority, and name of a folder/policydn
    pub fn request_certificate(&self, sub: &str, san: &[String], ca: &str, f: &str) -> bool {
        let mut payload = HashMap::new();
        // Sanity check CA and folder names
        if !self.cadns.contains_key(ca) {
            println!("No CA DN found for CA name {}", ca);
            return false
        }
        if !self.folders.contains_key(f) {
            println!("No policy DN found for folder name {}", f);
            return false
        }
        payload.insert("PolicyDN", self.folders.get(f).unwrap());
        payload.insert("CADN", self.cadns.get(ca).unwrap());
        // Need a better place to specify this thing
        let mut casahash = HashMap::new();
        casahash.insert("Name", "Validity Period");
        casahash.insert("Value", "365");
        let casavec = vec![casahash];
        payload.insert("CASpecificAttributes", casavec);
        // That's some ugly crap there
        payload.insert("Subject", sub);

        // Man there's a lot of awful anonymous hash arrays in this payload.
        // Kind of a pain to implement in Rust...
        let mut sans = Vec::new();
        while let Some(s) = san.pop() {
            let tn: HashMap<&str, &str> =
                [("Type","2"),("Name",s)].iter().cloned().collect();
            sans.push(tn);
        }
        if sans.len() > 1 {
            payload.insert("SubjectAltNames", sans);
        }

        let mut result = self.post("/Certificates/Request", &payload);
        if result.status.is_success() {
            println!("Successfully requested {}", sub);
            true
        } else {
            let stat = result.status;
            let mut why = String::new();
            result.read_to_string(&mut why).expect("Can't read response?!");
            println!("Received error {}: {:?}", stat, why);
            false
        }
    }

    // Do a request but with a CSR instead of subj/san.  Takes a name, csr,
    // cert authority, and folder name
    pub fn request_with_csr(&self, name: &str, csr: &str, ca: &str, f: &str) -> bool {
        // bluh
        true
    }

    // Send a renewal request given the DN of a certificate
    pub fn renew_certificate(&self, dn: &str) -> bool {
        let mut payload = HashMap::new();
        payload.insert("CertificateDN", &dn);
        result = self.post("/Certificates/Renew", payload);
        if result.status.is_success() {
            println!("Successfully submitted renewal request for {}", dn);
            true
        } else {
            let stat = result.status;
            let mut why = String::new();
            result.read_to_string(&mut why).expect("Can't read response?!");
            println!("Received error {}: {:?}", stat, why);
            false
        }
    }

    // Send a revoke request given the DN of a certificate
    pub fn revoke_certificate(&self, dn: &str) -> bool {
        let mut payload = HashMap::new();
        payload.insert("CertificateDN", &dn);
        payload.insert("Reason", "5");
        payload.insert("Comments", "Revoked via API");
        result = self.post("/Certificates/Revoke", payload);
        if result.status.is_success() {
            println!("Successfully submitted revoke request for {}", dn);
            true
        } else {
            let stat = result.status;
            let mut why = String::new();
            result.read_to_string(&mut why).expect("Can't read response?");
            println("Received error {}: {:?}", stat, why);
            false
        }
    }

    // Determine the revocation status of a certificate. Takes cert DN.
    pub fn check_revoked(&self, dn: &str) -> bool {
        // Two step process:
        // 1. Obtain vaultID via /Config/Read
        // 2. Obtain cert metadata via /X509CertificateStore/Retrieve
        // If the array TypedNameValues contains a hash with the name
        // 'Revocation Status' and a non-null value, certificate is revoked.
        true
    }
}
