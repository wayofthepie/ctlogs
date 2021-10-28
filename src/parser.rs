use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    //    X509(CertInfo),
    PreCert(PreCertMarker),
}

#[derive(Serialize, Deserialize)]
pub struct PreCertMarker {
    pub position: usize,
}

//#[derive(Default, Debug, Deserialize, Serialize)]
//pub struct CertInfo {
//    pub position: usize,
//    pub issuer: Vec<NamePart>,
//    pub subject: Vec<NamePart>,
//    pub san: Vec<SanObject>,
//    pub cert: String,
//}
//
