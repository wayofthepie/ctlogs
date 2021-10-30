use crate::{
    client::{CtClient, Logs},
    Message,
};
use anyhow::Result;
use der_parser::oid;
use futures::stream::{unfold, StreamExt, TryStreamExt};
use serde::{Deserialize, Serialize};
use tokio::{signal::unix::SignalKind, sync::mpsc::Sender};
use x509_parser::extensions::{
    GeneralName, ParsedExtension, SubjectAlternativeName, X509Extension,
};

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

pub async fn consume(client: impl CtClient, tx: Sender<Message>) -> Result<()> {
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
    match x509_parser::parse_x509_certificate(bytes) {
        Ok((_, cert)) => {
            let extensions = cert.extensions();
            // skip formatting this for now, the ".17" gets prefixed with a space, doesnt break
            // but looks weird
            #[rustfmt::skip]
            let san_oid = oid!(2.5.29.17);
            extensions
                .iter()
                .filter(|extension| extension.oid == san_oid)
                .for_each(|san| decode_san(san, msgs));
        }
        Err(err) => eprintln!("Error at position {}: {}", position, err),
    }
    Ok(())
}

fn decode_san(san: &X509Extension, msgs: &mut Vec<Message>) {
    if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names }) =
        san.parsed_extension()
    {
        for name in general_names.iter() {
            match name {
                GeneralName::OtherName(_, _) => {
                    // skip
                }
                GeneralName::RFC822Name(rfc822) => {
                    msgs.push(Message {
                        entry: rfc822.to_string(),
                    });
                }
                GeneralName::DNSName(dns) => {
                    msgs.push(Message {
                        entry: dns.to_string(),
                    });
                }
                GeneralName::DirectoryName(_) => {
                    // skip
                }
                GeneralName::URI(uri) => {
                    msgs.push(Message {
                        entry: uri.to_string(),
                    });
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
        }
    }
}

#[cfg(test)]
mod test {
    use super::consume;
    use crate::{
        client::{CtClient, LogEntry, Logs},
        Message,
    };
    use async_trait::async_trait;
    use std::{
        mem,
        ops::{Deref, DerefMut},
        sync::Arc,
    };
    use tokio::sync::Mutex;

    struct FakeClient {
        logs: Arc<Mutex<Logs>>,
    }

    #[async_trait]
    impl<'a> CtClient for FakeClient {
        async fn get_entries(&self, _: usize, _: usize) -> anyhow::Result<Logs> {
            let logs = self.logs.clone();
            let mut guard = logs.lock().await;
            let logs = mem::replace(&mut *(guard.deref_mut()), Logs { entries: vec![] });
            Ok(logs)
        }

        async fn get_tree_size(&self) -> anyhow::Result<usize> {
            Ok(self.logs.clone().lock().await.deref().entries.len())
        }
    }

    #[tokio::test]
    async fn consume_should_return_if_tree_size_is_zero() {
        let client = FakeClient {
            logs: Arc::new(Mutex::new(Logs { entries: vec![] })),
        };
        let (tx, _) = tokio::sync::mpsc::channel::<Message>(100);
        let result = consume(client, tx).await;
        assert!(result.is_ok())
    }

    #[tokio::test]
    async fn consume_should_send_all_logs_on_channel() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_cert").trim();
        let entry = LogEntry {
            leaf_input: leaf_input.to_owned(),
            ..LogEntry::default()
        };
        let logs = Arc::new(Mutex::new(Logs {
            entries: vec![entry],
        }));
        let client = FakeClient { logs };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(100);
        let handle = tokio::spawn(consume(client, tx));
        let mut count = 0;
        while rx.recv().await.is_some() {
            count += 1;
        }
        handle.await.unwrap().unwrap();
        assert_eq!(count, 2);
    }
}
