// External imports
extern crate reqwest;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate regex;
extern crate base64;
extern crate openssl;

use serde::{Serialize, Deserialize};

// Local modules
pub mod api;

// Structs and such
use std::collections::HashMap;

// JSON-based config file containing folder and cert authority names
#[derive(Deserialize, Debug)]
pub struct Config {
    pub folders: HashMap<String, String>,
    pub certauthorities: HashMap<String, String>
}

// Struct to hold authentication and server information
#[derive(Debug)]
pub struct Auth {
	pub user: String,
	pub pass: String,
	pub host: String
}

// Outbound certificate request, should support both with and w/o CSR
#[derive(Serialize)]
pub struct CertificateRequest {
    #[serde(rename="PolicyDN")]
    pub policydn: String,
    #[serde(rename="CADN")]
    pub cadn: String,
    #[serde(rename="CASpecificAttributes")]
    pub specific: Vec<HashMap<String, String>>,
    #[serde(rename="Subject")]
    pub subject: Option<String>,
    #[serde(rename="SubjectAltNames")]
    pub san: Option<Vec<HashMap<String, String>>>,
    #[serde(rename="ObjectName")]
    pub objectname: Option<String>,
    #[serde(rename="PKCS10")]
    pub csr: Option<String>
}

// Response from a call to Authorize
#[derive(Deserialize)]
pub struct VenafiAuth {
	#[serde(rename="APIKey")]
	pub apikey: String,
	#[serde(rename="ValidUntil")]
	pub validuntil: String
}

// JSON-defined list of certificates
#[derive(Deserialize)]
pub struct CertificateList {
    pub kind: String,
    pub items: Vec<CertificateHash>
}

#[derive(Deserialize)]
pub struct CertificateHash {
    #[serde(rename="commonName")]
    pub cn: String,
    #[serde(rename="certificateAuthority")]
    pub ca: String,
    #[serde(rename="subjectAlternativeNames")]
    pub san: Option<Vec<String>>
}

// Data returned by a call to /Config/FindObjectsOfClass
#[derive(Deserialize)]
pub struct FOOC {
    #[serde(rename="Objects")]
    pub objects: Vec<ClassObject>,
    #[serde(rename="Result")]
    pub result: i32
}

#[derive(Deserialize)]
pub struct ClassObject {
    #[serde(rename="AbsoluteGUID")]
    pub absguid: String,
    #[serde(rename="DN")]
    pub dn: String,
    #[serde(rename="GUID")]
    pub guid: String,
    #[serde(rename="Name")]
    pub name: String,
    #[serde(rename="Parent")]
    pub parent: String,
    #[serde(rename="TypeName")]
    pub typename: String
}

// Data returned by a call to /certificates/Retrieve
#[derive(Deserialize)]
pub struct RetrievedCert {
    #[serde(rename="CertificateData")]
    pub data: String,
    #[serde(rename="Filename")]
    pub filename: String,
    #[serde(rename="Format")]
    pub format: String
}

// Data returned by a call to /X509CertificateStore/Retrieve
#[derive(Deserialize)]
pub struct X509CertStore {
    #[serde(rename="Result")]
    pub result: String,
    #[serde(rename="CertificateString")]
    pub certificate: String,
    #[serde(rename="TypedNameValues")]
    pub typednamevalues: Vec<TypedNameValue>
}

#[derive(Deserialize)]
pub struct TypedNameValue {
    #[serde(rename="Type")]
    pub datatype: String,
    #[serde(rename="Name")]
    pub name: String,
    #[serde(rename="Value")]
    pub value: String
}

// Data returned by a call to /Config/Read
#[derive(Deserialize)]
pub struct ConfigRead {
    #[serde(rename="ObjectDN")]
    pub objectdn: String,
    #[serde(rename="AttributeName")]
    pub attribute: String,
    #[serde(rename="Values")]
    pub values: Vec<String>
}

// Little utility function to generate a random password if one is 
// required while fetching a certificate.
use rand::thread_rng;
use rand::Rng;


pub fn generate_pass() -> String {
	let mut rng = thread_rng();
    (0..30).map(|_| (0x20u8 + (rng.gen::<f32>() * 96.0) as u8) as char).collect()
}

