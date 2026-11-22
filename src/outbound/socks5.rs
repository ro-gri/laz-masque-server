//! Small RFC 1928/1929 client for a local upstream. All reads are exact and
//! bounded; callers apply a single deadline covering the complete handshake.
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use zeroize::Zeroizing;

use super::Proxy;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) async fn authenticate(proxy: &Proxy) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy.endpoint).await?;
    stream.set_nodelay(true)?;
    let method = if proxy.credentials.is_some() { 2 } else { 0 };
    stream.write_all(&[5, 1, method]).await?;
    let mut reply = [0; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, method] {
        return Err(invalid("SOCKS5 authentication method rejected"));
    }
    if let Some((username, password)) = &proxy.credentials {
        let mut request = Zeroizing::new(Vec::with_capacity(513));
        request.extend_from_slice(&[1, username.len() as u8]);
        request.extend_from_slice(username.as_bytes());
        request.push(password.len() as u8);
        request.extend_from_slice(password);
        stream.write_all(&request).await?;
        stream.read_exact(&mut reply).await?;
        if reply != [1, 0] {
            return Err(invalid("SOCKS5 authentication failed"));
        }
    }
    Ok(stream)
}

fn encode_address(target: SocketAddr, out: &mut Vec<u8>) {
    match target.ip().to_canonical() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
}

pub(super) async fn command(
    stream: &mut TcpStream,
    cmd: u8,
    target: SocketAddr,
) -> io::Result<SocketAddr> {
    let mut request = vec![5, cmd, 0];
    encode_address(target, &mut request);
    stream.write_all(&request).await?;
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 5 || reply[2] != 0 {
        return Err(invalid("invalid SOCKS5 reply"));
    }
    if reply[1] != 0 {
        return Err(io::Error::other(format!(
            "SOCKS5 request rejected (code {})",
            reply[1]
        )));
    }
    let ip = match reply[3] {
        1 => {
            let mut ip = [0; 4];
            stream.read_exact(&mut ip).await?;
            IpAddr::V4(Ipv4Addr::from(ip))
        }
        4 => {
            let mut ip = [0; 16];
            stream.read_exact(&mut ip).await?;
            IpAddr::V6(Ipv6Addr::from(ip))
        }
        3 if cmd == 1 => {
            // CONNECT's bound address is informational, not a new target.
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                return Err(invalid("empty SOCKS5 bound hostname"));
            }
            let mut name = [0; 255];
            stream.read_exact(&mut name[..len]).await?;
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
        _ => return Err(invalid("SOCKS5 UDP relay must advertise an IP address")),
    };
    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

pub(crate) struct UdpAssociation {
    control: TcpStream,
    header: Vec<u8>,
    target: SocketAddr,
    max_payload: usize,
    _active: OwnedSemaphorePermit,
}

pub(super) async fn associate(
    proxy: &Proxy,
    target: SocketAddr,
    active: OwnedSemaphorePermit,
) -> io::Result<(std::net::UdpSocket, Arc<UdpAssociation>)> {
    let mut control = authenticate(proxy).await?;
    let peer = control.peer_addr()?;
    let bind = SocketAddr::new(control.local_addr()?.ip(), 0);
    let socket = std::net::UdpSocket::bind(bind)?;
    let mut relay = command(&mut control, 3, socket.local_addr()?).await?;
    // Local SOCKS servers commonly return a wildcard listen address. Use
    // the authenticated control peer, never a kernel wildcard destination.
    if relay.ip().to_canonical().is_unspecified() {
        relay.set_ip(peer.ip());
    }
    if relay.port() == 0 || relay.ip().to_canonical() != peer.ip().to_canonical() {
        return Err(invalid("SOCKS5 UDP relay must use the control peer IP"));
    }
    socket.connect(relay)?;
    socket.set_nonblocking(true)?;
    let mut header = vec![0, 0, 0];
    encode_address(target, &mut header);
    let max_payload = proxy.udp_max_packet_size - header.len();
    Ok((
        socket,
        Arc::new(UdpAssociation {
            control,
            header,
            target,
            max_payload,
            _active: active,
        }),
    ))
}

impl UdpAssociation {
    /// Full SOCKS5 packet budget, including its IP header.
    pub(crate) fn max_packet_size(&self) -> usize {
        self.max_payload + self.header.len()
    }

    /// No legal application data travels on the association's TCP control
    /// channel after setup. EOF, error or unsolicited data tears it down.
    pub(crate) async fn closed(&self) -> io::Error {
        loop {
            if let Err(error) = self.control.readable().await {
                return error;
            }
            let mut byte = [0];
            match self.control.try_read(&mut byte) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return error,
                Ok(_) => {
                    return io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "SOCKS5 UDP control closed",
                    );
                }
            }
        }
    }

    pub(crate) fn encode(&self, payload: &[u8], out: &mut Vec<u8>) -> bool {
        out.clear();
        if payload.len() > self.max_payload {
            return false;
        }
        out.extend_from_slice(&self.header);
        out.extend_from_slice(payload);
        true
    }

    pub(crate) fn decode<'a>(&self, packet: &'a [u8]) -> Option<&'a [u8]> {
        // A peer may spell an IPv4 source as mapped IPv6, changing header
        // length. Enforce the complete packet budget in both directions.
        if packet.len() > self.max_payload + self.header.len() {
            return None;
        }
        let payload = decode_udp(packet, self.target)?;
        (payload.len() <= self.max_payload).then_some(payload)
    }
}

/// Reject fragments, malformed headers and responses from any destination
/// other than this tunnel's pinned target. The connected socket separately
/// filters the outer relay address and port.
pub(super) fn decode_udp(packet: &[u8], target: SocketAddr) -> Option<&[u8]> {
    if packet.get(..3)? != [0, 0, 0] {
        return None;
    }
    let (ip, port_at) = match *packet.get(3)? {
        1 => (
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(4..8)?).ok()?)),
            8,
        ),
        4 => (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(packet.get(4..20)?).ok()?,
            )),
            20,
        ),
        _ => return None,
    };
    let port = u16::from_be_bytes(packet.get(port_at..port_at + 2)?.try_into().ok()?);
    if ip.to_canonical() != target.ip().to_canonical() || port != target.port() {
        return None;
    }
    packet.get(port_at + 2..)
}

#[cfg(all(test, target_os = "linux"))]
mod batch_tests {
    use super::*;
    use crate::tunnel::udp::Socks5RecvBatch;
    use std::time::Duration;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn linux_socks_batch_filters_each_frame_and_preserves_boundaries() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_keepalive, _) = listener.accept().await.unwrap();
        let target: SocketAddr = "203.0.113.1:53".parse().unwrap();
        let mut header = vec![0, 0, 0];
        encode_address(target, &mut header);
        let association = UdpAssociation {
            control,
            header,
            target,
            max_payload: 200,
            _active: Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap(),
        };
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.connect(receiver.local_addr().unwrap()).unwrap();
        receiver
            .connect(sender.local_addr().unwrap())
            .await
            .unwrap();
        let frame = |data: &[u8]| {
            let mut bytes = Vec::new();
            assert!(association.encode(data, &mut bytes));
            bytes
        };
        let mut fragmented = frame(b"fragment");
        fragmented[2] = 1;
        let mut wrong_target = frame(b"wrong target");
        wrong_target[9] ^= 1;
        let mut reserved = frame(b"reserved");
        reserved[0] = 1;
        let mut mapped = vec![0, 0, 0, 4];
        mapped.extend_from_slice(
            &target
                .ip()
                .to_canonical()
                .to_string()
                .parse::<Ipv4Addr>()
                .unwrap()
                .to_ipv6_mapped()
                .octets(),
        );
        mapped.extend_from_slice(&target.port().to_be_bytes());
        mapped.extend_from_slice(b"mapped");
        // Small transport budget: detect both sentinel-size oversize and MSG_TRUNC.
        let mut batch = Socks5RecvBatch::new(&association, 64);
        let packets = [
            frame(b"first"),
            fragmented,
            frame(b""),
            wrong_target,
            vec![0, 0],
            reserved,
            mapped,
            frame(&[9; 65]),
            frame(&[8; 77]),
            frame(&[7; 200]),
            frame(&[6; 64]),
        ];
        for packet in &packets {
            sender.send(packet).unwrap();
        }
        let mut processed = 0;
        let mut payloads = Vec::new();
        let mut saw_batch = false;
        while processed < packets.len() {
            let n = tokio::time::timeout(Duration::from_secs(2), batch.recv(&receiver))
                .await
                .unwrap()
                .unwrap();
            processed += n;
            saw_batch |= n > 1;
            payloads.extend(batch.payloads(&association, n).map(<[u8]>::to_vec));
        }
        assert!(saw_batch);
        assert_eq!(processed, packets.len());
        assert_eq!(
            payloads,
            [b"first".to_vec(), vec![], b"mapped".to_vec(), vec![6; 64]]
        );
        // Reuse does not expose stale lengths/truncation flags or wait for a full batch.
        sender.send(&frame(b"next")).unwrap();
        let n = tokio::time::timeout(Duration::from_secs(2), batch.recv(&receiver))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            batch.payloads(&association, n).collect::<Vec<_>>(),
            [b"next".as_slice()]
        );
    }
}
