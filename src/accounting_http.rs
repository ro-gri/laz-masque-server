//! Loopback statistics and session-control API with bounded working storage.
use crate::accounting::Accounting;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
};

pub(crate) struct Server {
    listener: TcpListener,
    accounting: Arc<Accounting>,
    authenticators: Vec<Arc<crate::auth::SharedBasicAuthenticator>>,
}
impl Server {
    pub(crate) async fn bind(
        addr: SocketAddr,
        accounting: Arc<Accounting>,
        authenticators: Vec<Arc<crate::auth::SharedBasicAuthenticator>>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            accounting,
            authenticators,
        })
    }
    pub(crate) fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub(crate) fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let slots = Arc::new(Semaphore::new(4));
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                    accepted = self.listener.accept() => {
                        let Ok((stream, _)) = accepted else { tokio::time::sleep(Duration::from_millis(100)).await; continue; };
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        let accounting = self.accounting.clone();
                        let authenticators = self.authenticators.clone();
                        tasks.spawn(async move {
                            let _permit = permit;
                            let _ = tokio::time::timeout(Duration::from_secs(30), serve(stream, accounting, authenticators)).await;
                        });
                    }
                }
            }
        })
    }
}
async fn serve(
    mut stream: TcpStream,
    accounting: Arc<Accounting>,
    authenticators: Vec<Arc<crate::auth::SharedBasicAuthenticator>>,
) -> std::io::Result<()> {
    let mut request = Vec::new();
    loop {
        let mut buf = [0; 1024];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buf[..n]);
        if request.len() > 8192 {
            stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            return Ok(());
        }
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let first = request.split(|b| *b == b'\n').next().unwrap_or_default();
    if first == b"POST /kickAuth HTTP/1.1\r" || first == b"POST /kickAuth HTTP/1.0\r" {
        let Some(id) = kick_request(&mut stream, &mut request).await? else {
            return json_result(&mut stream, "400 Bad Request", false).await;
        };
        let mut success = true;
        let completions = match accounting.sessions.cancel(id) {
            Ok(completions) => completions,
            Err(()) => {
                success = false;
                Vec::new()
            }
        };
        // Do not short-circuit: cache cleanup is independent of session teardown,
        // and each listener must be attempted even if another one fails.
        for authenticator in authenticators {
            success &= authenticator.invalidate(id);
        }
        success &= crate::kick_auth::wait(completions).await;
        return json_result(
            &mut stream,
            if success {
                "200 OK"
            } else {
                "500 Internal Server Error"
            },
            success,
        )
        .await;
    }
    if first != b"GET /stats HTTP/1.1\r" && first != b"GET /stats HTTP/1.0\r" {
        stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        return Ok(());
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n").await?;
    let count = accounting.len();
    stream
        .write_all(
            format!(
                "{{\"instance_id\":\"{}\",\"traffic\":[",
                accounting.instance_id
            )
            .as_bytes(),
        )
        .await?;
    for start in (0..count).step_by(128) {
        let rows = accounting.batch(start, (start + 128).min(count));
        let mut output = Vec::with_capacity(rows.len() * 120);
        for (offset, row) in rows.into_iter().enumerate() {
            if start + offset != 0 {
                output.push(b',');
            }
            serde_json::to_writer(&mut output, &row)?;
        }
        stream.write_all(&output).await?;
    }
    stream.write_all(b"],\"online\":[").await?;
    let mut first = true;
    for start in (0..count).step_by(128) {
        let rows = accounting.batch(start, (start + 128).min(count));
        let mut output = Vec::with_capacity(128 * 40);
        for row in rows.into_iter().filter(|row| row.online) {
            if !first {
                output.push(b',');
            }
            first = false;
            serde_json::to_writer(&mut output, &row.id)?;
        }
        stream.write_all(&output).await?;
    }
    stream.write_all(b"]}").await?;
    stream.shutdown().await
}

async fn json_result(stream: &mut TcpStream, status: &str, ok: bool) -> std::io::Result<()> {
    let body = if ok {
        "{\"ok\":true}"
    } else {
        "{\"ok\":false}"
    };
    stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
    stream.shutdown().await
}

async fn kick_request(
    stream: &mut TcpStream,
    request: &mut Vec<u8>,
) -> std::io::Result<Option<uuid::Uuid>> {
    let end = request
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("complete headers")
        + 4;
    let Ok(headers) = std::str::from_utf8(&request[..end]) else {
        return Ok(None);
    };
    let mut length = None;
    let mut json = false;
    for line in headers
        .split("\r\n")
        .skip(1)
        .filter(|line| !line.is_empty())
    {
        let Some((name, value)) = line.split_once(':') else {
            return Ok(None);
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Ok(None);
            }
            length = value.parse::<usize>().ok();
            if length.is_none() {
                return Ok(None);
            }
        } else if name.eq_ignore_ascii_case("content-type") {
            if json || !value.eq_ignore_ascii_case("application/json") {
                return Ok(None);
            }
            json = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("origin")
        {
            return Ok(None);
        }
    }
    let Some(length) = length.filter(|n| *n > 0 && *n <= 256 && json) else {
        return Ok(None);
    };
    while request.len() < end + length {
        let mut buf = [0; 256];
        let remaining = (end + length - request.len()).min(buf.len());
        let n = stream.read(&mut buf[..remaining]).await?;
        if n == 0 {
            return Ok(None);
        }
        request.extend_from_slice(&buf[..n]);
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Kick {
        id: uuid::Uuid,
    }
    Ok(serde_json::from_slice::<Kick>(&request[end..end + length])
        .ok()
        .map(|kick| kick.id)
        .filter(|id| !id.is_nil()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    async fn get(addr: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }
    #[tokio::test]
    async fn kick_failure_still_clears_cache_and_attempts_every_session() {
        use crate::auth::{
            AuthPrecheck, BasicAuthenticator, SharedBasicAuthenticator, VerificationCredential,
        };
        let id = Uuid::new_v4();
        let config = crate::config::AccountingSection {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        };
        let accounting = Arc::new(Accounting::new(&config));
        let auth = Arc::new(SharedBasicAuthenticator::new(
            BasicAuthenticator::from_section(&crate::config::AuthSection {
                id,
                username: "alice".into(),
                password_hash: crate::auth::hash_password(b"secret").unwrap(),
                ..Default::default()
            })
            .unwrap(),
        ));
        let header = b"Basic YWxpY2U6c2VjcmV0";
        match auth.precheck(Some(header)) {
            AuthPrecheck::NeedsVerify {
                credential: VerificationCredential::File(credential),
                password,
            } => assert!(credential.verify(&password)),
            _ => panic!("expected cold authentication"),
        }
        assert!(matches!(
            auth.precheck(Some(header)),
            AuthPrecheck::Authenticated(_)
        ));
        let failed = accounting.acquire(Some(id));
        let healthy = accounting.acquire(Some(id));
        let failed_task = tokio::spawn(async move {
            failed.cancelled().await;
            failed.kick_failed();
        });
        let healthy_task = tokio::spawn(async move {
            healthy.cancelled().await;
        });
        let api = Server::bind(config.listen_addr.unwrap(), accounting, vec![auth.clone()])
            .await
            .unwrap();
        let addr = api.local_addr().unwrap();
        let task = api.spawn();
        let body = serde_json::json!({"id": id}).to_string();
        let request = format!(
            "POST /kickAuth HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let response = get(addr, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 500"), "{response}");
        assert_eq!(response.split_once("\r\n\r\n").unwrap().1, "{\"ok\":false}");
        failed_task.await.unwrap();
        healthy_task.await.unwrap();
        assert!(matches!(
            auth.precheck(Some(header)),
            AuthPrecheck::NeedsVerify { .. }
        ));
        let response = get(addr, request.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        for (headers, body) in [
            ("Content-Type: application/json\r\n", "{}".to_string()),
            (
                "Content-Type: application/json\r\n",
                serde_json::json!({"id": Uuid::nil()}).to_string(),
            ),
            (
                "Content-Type: application/json\r\n",
                serde_json::json!({"id": "invalid"}).to_string(),
            ),
            ("Content-Type: text/plain\r\n", body.clone()),
            (
                "Content-Type: application/json\r\nOrigin: http://example.test\r\n",
                body.clone(),
            ),
            (
                "Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n",
                body.clone(),
            ),
            (
                "Content-Type: application/json\r\nContent-Length: 0\r\n",
                body.clone(),
            ),
            ("Content-Type: application/json\r\n", " ".repeat(257)),
        ] {
            let response = get(
                addr,
                format!(
                    "POST /kickAuth HTTP/1.1\r\n{headers}Content-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
            assert!(response.starts_with("HTTP/1.1 400"), "{response}");
            assert_eq!(response.split_once("\r\n\r\n").unwrap().1, "{\"ok\":false}");
        }
        task.abort();
    }

    #[tokio::test]
    async fn streamed_batches_keep_all_rows_and_reads_never_clear_counters() {
        let config = crate::config::AccountingSection {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        };
        let accounting = Arc::new(Accounting::new(&config));
        let mut online = Vec::new();
        for n in 0..300 {
            let usage = accounting.acquire(Some(Uuid::new_v4()));
            usage.rx(n);
            usage.tx(2 * n);
            if n % 2 == 0 {
                online.push(usage.activate());
            }
        }
        let api = Server::bind(config.listen_addr.unwrap(), accounting.clone(), Vec::new())
            .await
            .unwrap();
        let addr = api.local_addr().unwrap();
        let task = api.spawn();
        let request = b"GET /stats HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let response = get(addr, request).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let value: serde_json::Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(value["instance_id"], accounting.instance_id.to_string());
        assert_eq!(value["traffic"].as_array().unwrap().len(), 300);
        assert_eq!(value["online"].as_array().unwrap().len(), 150);
        for (n, row) in value["traffic"].as_array().unwrap().iter().enumerate() {
            assert_eq!(row["rx_bytes"], n);
            assert_eq!(row["tx_bytes"], 2 * n);
        }
        drop(online);
        let response = get(addr, request).await;
        let after: serde_json::Value =
            serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(after["traffic"], value["traffic"]);
        assert_eq!(after["online"], serde_json::json!([]));
        assert!(
            get(addr, b"GET /stats?clear=1 HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 404")
        );
        assert!(
            get(addr, b"POST /stats HTTP/1.1\r\n\r\n")
                .await
                .starts_with("HTTP/1.1 404")
        );
        task.abort();
    }
}
