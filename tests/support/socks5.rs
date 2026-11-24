//! Deterministic SOCKS5 peer: records requested IPs and echoes payloads at
//! the proxy itself. Synthetic destinations therefore never reach a network.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::{JoinHandle, JoinSet};

pub struct MockSocks {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<(u8, SocketAddr)>>>,
    task: JoinHandle<()>,
}

impl MockSocks {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let recorded = Arc::clone(&recorded);
                        sessions.spawn(async move { let _ = echo(stream, recorded).await; });
                    }
                    _ = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
        });
        Self {
            addr,
            requests,
            task,
        }
    }
}
impl Drop for MockSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn echo(
    mut stream: TcpStream,
    recorded: Arc<Mutex<Vec<(u8, SocketAddr)>>>,
) -> std::io::Result<()> {
    let mut hello = [0; 3];
    stream.read_exact(&mut hello).await?;
    assert_eq!(hello, [5, 1, 0]);
    // Deliberately fragmented protocol response.
    stream.write_all(&[5]).await?;
    tokio::task::yield_now().await;
    stream.write_all(&[0]).await?;
    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    assert_eq!(request[0], 5);
    assert_eq!(request[2], 0);
    let ip = match request[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => panic!("target must be a checked IP, never a hostname"),
    };
    let target = SocketAddr::new(ip, stream.read_u16().await?);
    recorded.lock().unwrap().push((request[1], target));
    if request[1] == 1 {
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut buf = [0; 8192];
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                stream.shutdown().await?;
                return Ok(());
            }
            stream.write_all(&buf[..n]).await?;
        }
    }
    assert_eq!(request[1], 3);
    let udp = UdpSocket::bind("127.0.0.1:0").await?;
    let mut reply = vec![5, 0, 0, 1, 0, 0, 0, 0];
    reply.extend_from_slice(&udp.local_addr()?.port().to_be_bytes());
    stream.write_all(&reply).await?;
    let mut packet = vec![0; 65536];
    let mut control = [0];
    loop {
        tokio::select! {
            _ = stream.read(&mut control) => return Ok(()),
            received = udp.recv_from(&mut packet) => {
                let (len, peer) = received?;
                assert_eq!(peer, target);
                assert_eq!(&packet[..3], &[0, 0, 0]);
                let header = match packet[3] { 1 => 10, 4 => 22, _ => panic!("IP required") };
                assert!(len >= header);
                udp.send_to(&packet[..len], peer).await?;
            }
        }
    }
}
