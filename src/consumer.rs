use crate::parser::parse_logs;
use crate::{client::CtClient, parser::CertDetails};
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

#[derive(Debug)]
pub struct Message {
    pub position: usize,
    pub result: anyhow::Result<CertDetails>,
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
        for msg in fut.await {
            tx.send(Message {
                position: msg.0,
                result: msg.1,
            })
            .await?;
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

#[cfg(test)]
mod test {
    use super::{consume, Message};
    use crate::client::{CtClient, LogEntry, Logs, Operators};
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
        async fn list_log_operators(&self) -> anyhow::Result<Operators> {
            todo!()
        }

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
        while let Some(msg) = rx.recv().await {
            assert!(msg.result.is_ok());
            for _ in msg.result.unwrap().san {
                count += 1;
            }
        }
        handle.await.unwrap().unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn consume_should_return_error_if_parsing_cert_fails() {
        let leaf_input = include_str!("../resources/test/leaf_input_with_invalid_cert").trim();
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
        while let Some(msg) = rx.recv().await {
            assert!(msg.result.is_err());
            assert!(format!("{}", msg.result.err().unwrap()).contains("Error at position 0"));
            count += 1;
        }
        handle.await.unwrap().unwrap();
        assert_eq!(count, 1);
    }
}
