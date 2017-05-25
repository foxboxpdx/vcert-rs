// types.rs
// Define structs for Serde to serialize/deserialize from representing
// some of the more common pieces of data we'll encounter with Venafi

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
    pub result: String
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

