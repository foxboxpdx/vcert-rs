// types.rs
// Define structs for Serde to serialize/deserialize from representing
// some of the more common pieces of data we'll encounter with Venafi
use std::collections::HashMap;
use openssl::pkcs12::Pkcs12;

// JSON-based config file containing folder and cert authority names
#[derive(Deserialize, Debug)]
pub struct ZerdaConfig {
    pub kind: String,
    pub folders: HashMap<String, String>,
    pub certauthorities: HashMap<String, String>,
    pub f5basedns: HashMap<String, String>,
    pub f5params: HashMap<String, String>
}

// I'm way too lazy to deal with figuring out a way to return a P12 and its
// password as a vector or hashmap or something sane so eff it here's a struct.
pub struct P12Bundle {
    pub p12: Pkcs12,
    pub pwd: String
}

// Outbound certificate request, should support both with and w/o CSR
// It's either this or that gross serde::json::Map mess
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
    pub pkcs10: Option<String>
}

// Outbound app creation request
#[derive(Serialize)]
pub struct CreateAppRequest {
    #[serde(rename="ObjectDN")]
    pub objectdn: String,
    #[serde(rename="Class")]
    pub class: String,
    #[serde(rename="NameAttributeList")]
    pub nal: Vec<NameAttrib>
}

#[derive(Serialize)]
pub struct NameAttrib {
    #[serde(rename="Name")]
    pub name: String,
    #[serde(rename="Value")]
    pub value: String
}

// Outbound request to /Config/WriteDN
#[derive(Serialize)]
pub struct WriteDNRequest {
    #[serde(rename="ObjectDN")]
    pub objectdn: String,
    #[serde(rename="AttributeName")]
    pub attrib: String,
    #[serde(rename="Values")]
    pub values: Vec<String>
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

