pub mod client;
mod consumer;
mod parser;
use again::RetryPolicy;

use crate::client::{CtClient, HttpCtClientBuilder};
use std::time::Duration;

const CT_LOGS_URL: &str = "https://ct.googleapis.com/logs/argon2021/ct/v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    //    let nc = async_nats::Options::new()
    //        .reconnect_callback(|| println!("reconnecting..."))
    //        .close_callback(|| println!("closed"))
    //        .connect("nats://localhost:4222")
    //        .await?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<consumer::Message>(100);
    let client = HttpCtClientBuilder::default()
        .base_url(CT_LOGS_URL)
        .retry_policy(RetryPolicy::fixed(Duration::from_millis(10)).with_max_retries(10))
        .timeout(Duration::from_secs(20))
        .build()?;

    let operators = client.list_log_operators().await?;

    for operator in operators.operators {
        println!("{:#?}", operator.name);
        for log in operator.logs {
            println!("{:#?}", log);
        }
    }

    let handle = tokio::spawn(consumer::consume(client, tx));
    while let Some(msg) = rx.recv().await {
        match msg.result {
            Ok(result) => println!("{:#?}", result),
            Err(_) => eprintln!("failed"),
        }
    }
    handle.await??;
    Ok(())
}
