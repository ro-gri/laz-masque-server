//! Read-only loopback API. Output is streamed with bounded working storage.
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
}
impl Server {
    pub(crate) async fn bind(
        addr: SocketAddr,
        accounting: Arc<Accounting>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            accounting,
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
                        tasks.spawn(async move {
                            let _permit = permit;
                            let _ = tokio::time::timeout(Duration::from_secs(30), serve(stream, accounting)).await;
                        });
                    }
                }
            }
        })
    }
}
async fn serve(mut stream: TcpStream, accounting: Arc<Accounting>) -> std::io::Result<()> {
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
        let api = Server::bind(config.listen_addr.unwrap(), accounting.clone())
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
