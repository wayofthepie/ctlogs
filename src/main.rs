use std::time::Duration;

use crate::client::HttpCtClient;

pub mod client;
mod consumer;
mod parser;

const CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2021/ct/v1";

#[derive(Debug)]
pub struct Message {
    entry: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let nc = async_nats::Options::new()
        .reconnect_callback(|| println!("reconnecting..."))
        .close_callback(|| println!("closed"))
        .connect("nats://localhost:4222")
        .await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Message>(100);
    let client = HttpCtClient::new(
        CT_LOGS_URL,
        Duration::from_millis(500),
        Duration::from_secs(20),
    );
    let handle = tokio::spawn(consumer::consume(client, tx));
    while let Some(msg) = rx.recv().await {
        let bytes = msg.entry.as_bytes();
        let len = bytes.len();
        // stay below 1MiB limit
        if len < 1048576 {
            nc.publish("domains", bytes).await?
        }
    }
    handle.await??;
    Ok(())
}
