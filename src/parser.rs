use crate::client::Logs;
use anyhow::{anyhow, Result};
use der_parser::oid;
use x509_parser::{
    extensions::{GeneralName, ParsedExtension, SubjectAlternativeName, X509Extension},
    prelude::oid_registry,
};

#[derive(Debug)]
pub struct CertDetails {
    pub subject: String,
    pub san: Vec<String>,
}

pub async fn parse_logs(logs: Logs) -> Vec<(usize, Result<CertDetails>)> {
    let mut msgs = vec![];
    for (position, entry) in logs.entries.iter().enumerate() {
        match base64::decode(&entry.leaf_input) {
            Ok(bytes) => {
                let entry_type = bytes[10] + bytes[11];
                if entry_type == 0 {
                    let cert_end_index =
                        u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]) as usize + 15;
                    msgs.push((
                        position,
                        parse_x509_bytes(&bytes[15..cert_end_index], position),
                    ));
                }
            }
            Err(_) => msgs.push((
                position,
                Err(anyhow!("Failed to base64 decode certificate")),
            )),
        }
    }
    msgs
}

fn parse_x509_bytes(bytes: &[u8], position: usize) -> Result<CertDetails> {
    match x509_parser::parse_x509_certificate(bytes) {
        Ok((_, cert)) => {
            let subject = cert.subject().to_string_with_registry(oid_registry())?;
            let extensions = cert.extensions();
            // skip formatting this for now, the ".17" gets prefixed with a space, doesnt break
            // but looks weird
            #[rustfmt::skip]
            let san_oid = oid!(2.5.29.17);
            let san = extensions
                .iter()
                .filter(|extension| extension.oid == san_oid)
                .map(decode_san)
                .flatten()
                .collect();
            let details = CertDetails { subject, san };
            Ok(details)
        }
        Err(err) => Err(anyhow!("Error at position {}: {}", position, err)),
    }
}

fn decode_san(san: &X509Extension) -> Vec<String> {
    if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names }) =
        san.parsed_extension()
    {
        general_names.iter().fold(Vec::new(), |mut acc, name| {
            match name {
                GeneralName::OtherName(_, _) => {
                    // skip
                }
                GeneralName::RFC822Name(rfc822) => {
                    acc.push(rfc822.to_string());
                }
                GeneralName::DNSName(dns) => {
                    acc.push(dns.to_string());
                }
                GeneralName::DirectoryName(_) => {
                    // skip
                }
                GeneralName::URI(uri) => {
                    acc.push(uri.to_string());
                }
                GeneralName::IPAddress(_) => {
                    // skip
                }
                GeneralName::RegisteredID(_) => {
                    // skip
                }
                GeneralName::X400Address(_) => todo!(),
                GeneralName::EDIPartyName(_) => todo!(),
            }
            acc
        })
    } else {
        vec![]
    }
}
