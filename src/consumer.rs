use std::time::Duration;

use crate::{
    client::{CtClient, HttpCtClient, Logs},
    Message,
};
use anyhow::Result;
use futures::stream::{unfold, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use tokio::{signal::unix::SignalKind, sync::mpsc::Sender};

const RETRIEVAL_LIMIT: usize = 31;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct CertInfo {
    position: usize,
    issuer: Vec<NamePart>,
    subject: Vec<NamePart>,
    cert: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct NamePart {
    tag: String,
    value: String,
}

pub async fn consume(base_url: &str, tx: Sender<Message>) -> Result<()> {
    let client = HttpCtClient::new(
        base_url,
        Duration::from_millis(500),
        Duration::from_secs(20),
    );
    let tree_size = client.get_tree_size().await?;
    unfold((0, 0), |(start, end)| async move {
        (start < tree_size).then(|| {
            (
                (start, end + RETRIEVAL_LIMIT),
                (start + RETRIEVAL_LIMIT + 1, end + RETRIEVAL_LIMIT + 1),
            )
        })
    })
    .map(|(start, end)| client.get_entries(start, end))
    .take_until(sigint_handler())
    .buffer_unordered(20)
    .map_ok(parse_logs)
    .try_for_each(|fut| async {
        for msg in fut.await? {
            tx.send(msg).await?;
        }
        Ok(())
    })
    .await?;
    Ok(())
}

async fn sigint_handler() -> Result<()> {
    let mut signal = tokio::signal::unix::signal(SignalKind::interrupt())?;
    signal.recv().await;
    eprintln!("\nAttempting to gracefully let tasks complete.\n");
    Ok(())
}

async fn parse_logs(logs: Logs) -> Result<Vec<Message>> {
    let mut msgs = vec![];
    for (position, entry) in logs.entries.iter().enumerate() {
        let bytes = base64::decode(&entry.leaf_input)?;
        let entry_type = bytes[10] + bytes[11];
        if entry_type == 0 {
            let cert_end_index =
                u32::from_be_bytes([0, bytes[12], bytes[13], bytes[14]]) as usize + 15;
            parse_x509_bytes(&bytes[15..cert_end_index], position, &mut msgs)?;
        }
    }
    Ok(msgs)
}

fn parse_x509_bytes(bytes: &[u8], position: usize, msgs: &mut Vec<Message>) -> Result<()> {
    match x509_parser::parse_x509_certificate(&bytes) {
        Ok((_, cert)) => {
            msgs.push(Message {
                entry: format!("{:#?}", cert.tbs_certificate),
            });

            //let extensions = cert.extensions();
            //// skip formatting this for now, the ".17" gets prefixed with a space, doesnt break
            //// but looks weird
            //#[rustfmt::skip]
            //let san_oid = oid!(2.5.29.17);
            //let san = extensions.get(&san_oid);
            //if let Some(san) = san {
            //    if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName {
            //        general_names,
            //    }) = san.parsed_extension()
            //    {
            //        for name in general_names.iter() {
            //            match name {
            //                GeneralName::OtherName(_, bytes) => {
            //                    // skip
            //                }
            //                GeneralName::RFC822Name(rfc822) => {
            //                    msgs.push(Message {
            //                        entry: rfc822.to_string(),
            //                    });
            //                }
            //                GeneralName::DNSName(dns) => {
            //                    msgs.push(Message {
            //                        entry: dns.to_string(),
            //                    });
            //                }
            //                GeneralName::DirectoryName(_) => {
            //                    // skip
            //                }
            //                GeneralName::URI(uri) => {
            //                    msgs.push(Message {
            //                        entry: uri.to_string(),
            //                    });
            //                }
            //                GeneralName::IPAddress(addr) => {
            //                    // skip
            //                }
            //                GeneralName::RegisteredID(_) => {
            //                    // skip
            //                }
            //            }
            //        }
            //    }
            //};
        }
        Err(err) => eprintln!("Error at position {}: {}", position, err),
    }
    Ok(())
}
