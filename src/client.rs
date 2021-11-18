use again::{self, RetryPolicy};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct Logs {
    pub entries: Vec<LogEntry>,
}

#[derive(Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub struct LogEntry {
    /// The `leaf_input` field is a `String` of base64 encoded data. The data is a DER encoded
    /// MerkleTreeHeader, which has the following structure.
    /// ```
    /// [0] [1] [2..=9] [10..=11] [12..=14] [15..]
    /// |   |     |        |         |      |
    /// |   |     |        |         |      |- rest
    /// |   |     |        |         |
    /// |   |     |        |         |- length
    /// |   |     |        |
    /// |   |     |        | - log entry type
    /// |   |     |
    /// |   |     | - timestamp
    /// |   |
    /// |   | - signature type
    /// |
    /// | - version
    /// ```
    ///
    pub leaf_input: String,
    pub extra_data: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct STH {
    pub tree_size: usize,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operators {
    pub operators: Vec<Operator>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Log {
    pub description: String,
    pub log_id: String,
    pub key: String,
    pub url: String,
    pub mmd: i64,
    pub state: State,
    pub temporal_interval: Option<TemporalInterval>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub usable: Option<Usable>,
    pub readonly: Option<Readonly>,
    pub retired: Option<Retired>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Usable {
    pub timestamp: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Readonly {
    pub timestamp: String,
    pub final_tree_head: FinalTreeHead,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FinalTreeHead {
    pub sha256_root_hash: String,
    pub tree_size: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Retired {
    pub timestamp: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalInterval {
    pub start_inclusive: String,
    pub end_exclusive: String,
}

#[async_trait]
pub trait CtClient {
    async fn list_log_operators(&self, base_url: &str) -> anyhow::Result<Operators>;
    async fn get_entries(&self, start: usize, end: usize) -> anyhow::Result<Logs>;
    async fn get_tree_size(&self) -> anyhow::Result<usize>;
}

#[derive(Clone)]
pub struct HttpCtClient<'a> {
    base_url: &'a str,
    client: Client,
    timeout: Duration,
    retry_policy: RetryPolicy,
}

impl<'a> HttpCtClient<'a> {
    pub fn new(base_url: &'a str, retry: Duration, timeout: Duration) -> Self {
        let policy = RetryPolicy::fixed(retry).with_max_retries(10);
        let client = Client::new();
        Self {
            base_url,
            client,
            timeout,
            retry_policy: policy,
        }
    }
}

#[async_trait]
impl<'a> CtClient for HttpCtClient<'a> {
    /// The base url for listing log operators is different from the base url for other
    /// operations on [HttpCtClient](self::HttpCtClient).
    async fn list_log_operators(&self, base_url: &str) -> anyhow::Result<Operators> {
        let operators = self
            .retry_policy
            .retry_if(
                || async {
                    self.client
                        .get(&format!("{}/log_list.json", base_url))
                        .timeout(self.timeout)
                        .send()
                        .await
                        .and_then(|response| response.error_for_status())?
                        .json::<Operators>()
                        .await
                },
                |err: &reqwest::Error| {
                    reqwest::Error::is_status(err) || reqwest::Error::is_timeout(err)
                },
            )
            .await?;
        Ok(operators)
    }

    async fn get_entries(&self, start: usize, end: usize) -> anyhow::Result<Logs> {
        let mut logs = self
            .retry_policy
            .retry_if(
                || async {
                    self.client
                        .get(&format!("{}/get-entries", self.base_url))
                        .query(&[("start", start), ("end", end)])
                        .timeout(self.timeout)
                        .send()
                        .await
                        .and_then(|response| response.error_for_status())?
                        .json::<Logs>()
                        .await
                },
                |err: &reqwest::Error| {
                    reqwest::Error::is_status(err) || reqwest::Error::is_timeout(err)
                },
            )
            .await?;
        while logs.entries.len() < end - start + 1 {
            let len = logs.entries.len();
            let new_start = start + len;
            let next = self.get_entries(new_start, end).await?;
            logs.entries.extend(next.entries);
        }
        Ok(logs)
    }

    async fn get_tree_size(&self) -> anyhow::Result<usize> {
        let response = self
            .retry_policy
            .retry_if(
                || async {
                    self.client
                        .get(&format!("{}/get-sth", self.base_url))
                        .timeout(self.timeout)
                        .send()
                        .await
                        .and_then(|response| response.error_for_status())
                },
                |err: &reqwest::Error| {
                    reqwest::Error::is_status(err) || reqwest::Error::is_timeout(err)
                },
            )
            .await?;
        Ok(response.json::<STH>().await?.tree_size)
    }
}

#[cfg(test)]
mod test {
    use super::{Logs, Operator, STH};
    use crate::client::{CtClient, HttpCtClient, LogEntry, Operators};
    use std::time::Duration;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    const LEAF_INPUT: &str = include_str!("../resources/test/leaf_input_with_cert");

    fn default_client(uri: &str) -> HttpCtClient {
        HttpCtClient::new(uri, Duration::from_millis(1), Duration::from_secs(20))
    }

    #[tokio::test]
    async fn get_num_entries_should_fail_if_api_call_fails() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_tree_size().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_num_entries_should_return_size() {
        let expected_size: usize = 12;
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(STH {
                tree_size: expected_size,
            }))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_tree_size().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_size);
    }

    #[tokio::test]
    async fn get_entries_should_fail_if_log_retrieval_fails() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_entries_should_fail_if_body_is_not_an_expected_value() {
        let body: Vec<u32> = vec![0, 0];
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_entries_should_return_logs() {
        let body = Logs {
            entries: vec![
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
            ],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }

    #[tokio::test]
    async fn get_entries_should_retry_on_failure() {
        let body = Logs {
            entries: vec![
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
            ],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;

        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_entries(0, 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }

    #[tokio::test]
    async fn get_tree_size_should_retry_on_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(400))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(STH { tree_size: 0 }))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = default_client(uri);
        let result = client.get_tree_size().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn get_tree_size_should_retry_on_timeout() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(50)))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/get-sth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(STH { tree_size: 0 }))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri, Duration::from_millis(10), Duration::from_millis(10));
        let result = client.get_tree_size().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn get_entries_should_retry_on_timeout() {
        let body = Logs {
            entries: vec![
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
                LogEntry {
                    leaf_input: LEAF_INPUT.to_owned(),
                    extra_data: "".to_owned(),
                },
            ],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(50)))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/get-entries"))
            .and(query_param("start", "0"))
            .and(query_param("end", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&mock_server)
            .await;
        let uri = &mock_server.uri();
        let client = HttpCtClient::new(uri, Duration::from_millis(10), Duration::from_millis(10));
        let result = client.get_entries(0, 1).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }

    #[tokio::test]
    async fn list_log_operators_should_return_operators() {
        let body = Operators {
            operators: vec![Operator {
                name: "Google".to_owned(),
                email: vec!["google-ct-logs@googlegroups.com".to_owned()],
                logs: vec![],
            }],
        };
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/log_list.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;
        let uri = mock_server.uri();
        let client = default_client(&uri);
        let result = client.list_log_operators(&uri).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), body);
    }
}
