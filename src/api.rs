// Define a struct and implement functions on it for making various API calls
// to the Venafi TPP.
use super::*;
use std::collections::HashMap;
use std::io::Read;
use base64::decode;

// Define the API struct
#[derive(Debug)]
pub struct VenafiAPI {
    auth: Auth,
    apikey: String,
    config: Config
}


impl VenafiAPI {
    
    // Authenticate to receive the API Key necessary for all operations
    // Returns Ok(()) and sets self.apikey on success; reqwest::Error) on
    // failure.
    pub fn get_api_key(&mut self) -> Result<(), reqwest::Error> {
        let body: HashMap<&str, String> =
        [("Username", self.auth.user.clone()),
         ("Password", self.auth.pass.clone())].iter().cloned().collect();
        
        let client = reqwest::Client::new();
        let uri = format!("{}/Authorize/", self.auth.host);
        let authdata: VenafiAuth = client.get(&uri)
            .json(&body)
            .send()?
            .json()?;
        self.apikey = authdata.apikey;
        Ok(())
    }
    
    // Retrieve metadata for X509 Server Certificates available to the
    // authenticated user.  Uses contents of self.config.folders to
    // determine which top-level policyDNs to query.
    pub fn fetch_cert_metadata(&self) -> Result<HashMap<String, String>, String> {
        Ok(HashMap::new())
        
    }
    
    // Attempt to retrieve a certificate given the full DN of the cert
    // object, in the specified format, with flags for including the
    // Chain and/or the PrivKey.  A random password is generated in the
    // latter case, as one is required for encrypting the PKey.
    // Returns a tuple of the Base64 decoded cert and its password (if 
    // any) on success, or an Err(String, String) on failure containing
    // the HTTP code and an error message for callers to handle.
    pub fn fetch_certificate(&self, dn: &str, fmt: &str, ch: bool, pkey: bool) -> 
        Result<(String, String), (i32, String)> {
            
        Ok(("foo".to_string(), "bar".to_string()))
    }
    
    // Attempt to retrieve the expiration date of a certificate given
    // the full DN of the cert object.  Returns a String containing the
    // date on success, or an Err(String) containing an error message
    // on failure.
    pub fn fetch_expiry(&self, dn: &str) -> Result<String, String> {
        Ok("foo".to_string())
        
    }
    
    // Attempt to request a new certificate given a Subject, an optional
    // Vec of SubjectAlternativeNames, a Certificate Authority matching
    // one of those defined in self.config, and a folder (aka PolicyDN)
    // matching one of those defined in self.config.  Returns a String
    // representing the CertificateDN of the newly-created cert on 
    // success, or an Err(String) with a failure reason on failure.
    pub fn request_certificate(&self, subj: &str, san: Vec<&str>, ca: &str, pdn: &str) -> Result<String, String> {
        Ok("foo".to_string())
        
    }
    
    // Attempt to request a new certificate given a CSR (PKCS#10), and a
    // Certificate Authority and PolicyDN as defined in self.config.
    // Returns a String representing the CertificateDN of the newly-
    // created cert on success, or an Err(String) with a reason on failure.
    pub fn request_with_csr(&self, csr: &str, ca: &str, pdn: &str) -> Result<String, String> {
        Ok("foo".to_string())
        
    }
    
    // Attempt to renew an existing certificate, given its full DN.
    // Returns Ok(()) on success and Err(String) on failure.
    pub fn renew_certificate(&self, dn: &str) -> Result<(), String> {
        Ok(())
        
    }
    
    // Attempt to revoke an existing certificate, given its full DN.
    // Returns Ok() on success, Err(String) on failure.
    pub fn revoke_certificate(&self, dn: &str) -> Result<(), String> {
        Ok(())
        
    }
    
    // Check the revocation status of an existing certificate, given its
    // full DN.  Returns a bool indicating whether the cert has been
    // revoked or not, or an Err(String) with a failure reason.
    pub fn is_revoked(&self, dn: &str) -> Result<bool, String> {
        Ok(true)
        
    }
    
    // Private functions to minimize repeating code.  Automatically add
    // the API key into the headers.
    
    // Given a URI, make an HTTP GET call.  Returns either JSON
    // from the GET result, or a reqwest::Error.
    fn get(&self, uri: &str) -> Result<String, reqwest::Error> {
        let client = reqwest::Client::new();
        let fulluri = format!("{}/{}", self.auth.host, uri);
        let res = client.get(&fulluri)
            .header("X-Venafi-Api-Key", self.apikey.clone())
            .send()?
            .text()?;
        Ok(res)
    }
    
    // Given a URI and a piece of data that implements Serde's 'Serialize'
    // trait, serialize the data to JSON and POST it to the uri.
    fn post<T>(&self, uri: &str, data: T) -> Result<String, reqwest::Error> where T: serde::Serialize {
        let client = reqwest::Client::new();
        let fulluri = format!("{}/{}", self.auth.host, uri);
        let res = client.post(&fulluri)
            .header("X-Venafi-Api-Key", self.apikey.clone())
            .json(&data)
            .send()?
            .text()?;
        Ok(res)
    }
}
