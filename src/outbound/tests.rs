use super::*;
use crate::config::Socks5Section;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[path = "../../tests/support/socks5.rs"]
mod mock;

fn config(endpoint: SocketAddr) -> OutboundSection {
    OutboundSection {
        default_route: OutboundRoute::Socks5,
        direct_cidrs: vec![
            "192.0.2.0/25".into(),
            "192.0.2.64/26".into(),
            "2001:db8::/32".into(),
        ],
        socks5: Some(Socks5Section {
            endpoint,
            max_udp_associations: 1,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn routes_boundaries_and_mapped_ipv4_without_overrides_of_acl() {
    let router = Router::load(&config("127.0.0.1:1080".parse().unwrap())).unwrap();
    for addr in [
        "192.0.2.0",
        "192.0.2.127",
        "::ffff:192.0.2.64",
        "2001:db8::1",
    ] {
        assert_eq!(
            router.route(addr.parse().unwrap()),
            OutboundRoute::Direct,
            "{addr}"
        );
    }
    for addr in ["192.0.2.128", "192.0.1.255", "2001:db9::1", "::1"] {
        assert_eq!(
            router.route(addr.parse().unwrap()),
            OutboundRoute::Socks5,
            "{addr}"
        );
    }
    let default = Router::load(&OutboundSection::default()).unwrap();
    assert_eq!(
        default.route("203.0.113.1".parse().unwrap()),
        OutboundRoute::Direct
    );
}

#[test]
fn invalid_config_is_rejected_without_network_io() {
    let mut c = config("127.0.0.1:1080".parse().unwrap());
    c.direct_cidrs.push("invalid".into());
    assert!(Router::load(&c).is_err());
    c.direct_cidrs.clear();
    c.socks5.as_mut().unwrap().endpoint = "192.0.2.1:1080".parse().unwrap();
    assert!(Router::load(&c).is_err());
    c.socks5 = None;
    assert!(Router::load(&c).is_err());
}

#[tokio::test]
async fn tcp_connect_uses_ip_and_preserves_payload_and_half_close() {
    let proxy = mock::MockSocks::start().await;
    let router = Router::load(&config(proxy.addr)).unwrap();
    for target in ["203.0.113.1:443", "[2001:db9::1]:443"] {
        let mut stream = router.connect_tcp(target.parse().unwrap()).await.unwrap();
        stream.write_all(b"checked IP").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut payload = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut payload))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(payload, b"checked IP");
    }
    assert_eq!(proxy.requests.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn direct_bypasses_upstream_but_proxy_failure_never_falls_back() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let absent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut c = config(absent.local_addr().unwrap());
    drop(absent);
    let router = Router::load(&c).unwrap();
    assert!(
        router
            .connect_tcp(target.local_addr().unwrap())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), target.accept())
            .await
            .is_err()
    );
    c.direct_cidrs = vec!["127.0.0.0/8".into()];
    let router = Router::load(&c).unwrap();
    let stream = router
        .connect_tcp(target.local_addr().unwrap())
        .await
        .unwrap();
    assert!(target.accept().await.is_ok());
    drop(stream);
}

#[tokio::test]
async fn udp_association_echo_limits_and_control_lifetime() {
    let proxy = mock::MockSocks::start().await;
    let router = Router::load(&config(proxy.addr)).unwrap();
    let target = "203.0.113.1:53".parse().unwrap();
    let (socket, association) = router.associate(target).await.unwrap();
    assert!(router.associate(target).await.is_err());
    let socket = UdpSocket::from_std(socket).unwrap();
    for payload in [vec![], vec![7; 1200], vec![1; 4096]] {
        let mut packet = Vec::new();
        assert!(association.encode(&payload, &mut packet));
        socket.send(&packet).await.unwrap();
        let mut buffer = vec![0; 65536];
        let n = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(association.decode(&buffer[..n]), Some(payload.as_slice()));
    }
    assert!(association.encode(&vec![0; 65497], &mut Vec::new()));
    assert!(!association.encode(&vec![0; 65498], &mut Vec::new()));
    drop(association);
    let (_, association) = router.associate(target).await.unwrap();
    drop(proxy);
    tokio::time::timeout(Duration::from_secs(2), association.closed())
        .await
        .unwrap();
    drop(association);
    assert_eq!(
        router
            .proxy
            .as_ref()
            .unwrap()
            .associations
            .available_permits(),
        1
    );
}

#[test]
fn udp_codec_rejects_bad_headers_fragments_and_wrong_sources() {
    let target = "203.0.113.1:53".parse().unwrap();
    let good = vec![0, 0, 0, 1, 203, 0, 113, 1, 0, 53, 42];
    assert_eq!(socks5::decode_udp(&good, target), Some(&[42][..]));
    for len in 0..10 {
        assert!(socks5::decode_udp(&good[..len], target).is_none());
    }
    for index in [0, 1, 2, 3, 4, 9] {
        let mut bad = good.clone();
        bad[index] = bad[index].wrapping_add(1);
        assert!(socks5::decode_udp(&bad, target).is_none());
    }
}

#[tokio::test]
async fn setup_deadline_and_cancellation_release_connecting_capacity() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router = Router::load(&config(listener.local_addr().unwrap())).unwrap();
    let result = tokio::time::timeout(
        Duration::from_millis(30),
        router.connect_tcp("203.0.113.1:443".parse().unwrap()),
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        router
            .proxy
            .as_ref()
            .unwrap()
            .connecting
            .available_permits(),
        128
    );
}

struct TempFile(std::path::PathBuf);
impl TempFile {
    fn new(contents: &[u8]) -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "masque-outbound-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).unwrap();
        Self(path)
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn file_snapshots_are_immutable_and_changes_have_distinct_fingerprints() {
    let file = TempFile::new(b"# synthetic fixture\n192.0.2.0/24\n");
    let mut c = config("127.0.0.1:1080".parse().unwrap());
    c.direct_cidrs.clear();
    c.direct_cidrs_file = Some(file.0.clone());
    let loaded = Router::load(&c).unwrap();
    std::fs::write(&file.0, b"203.0.113.0/24\n").unwrap();
    let changed = Router::load(&c).unwrap();
    assert_ne!(loaded.files_digest(), changed.files_digest());
    assert_eq!(
        loaded.route("192.0.2.1".parse().unwrap()),
        OutboundRoute::Direct
    );
    assert_eq!(
        changed.route("192.0.2.1".parse().unwrap()),
        OutboundRoute::Socks5
    );
    for bad in ["# empty", "192.0.2.0/24\ninvalid"] {
        std::fs::write(&file.0, bad).unwrap();
        assert!(Router::load(&c).is_err());
    }
}

#[tokio::test]
async fn password_authentication_and_no_downgrade() {
    let password = TempFile::new(b"synthetic-password\n");
    for accept in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut c = config(listener.local_addr().unwrap());
        let proxy = c.socks5.as_mut().unwrap();
        proxy.username = Some("fixture".into());
        proxy.password_file = Some(password.0.clone());
        let router = Router::load(&c).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            if !accept {
                // A server choosing unauthenticated mode must not downgrade.
                stream.write_all(&[5, 0]).await.unwrap();
                return;
            }
            stream.write_all(&[5, 2]).await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), 1);
            let mut username = vec![0; stream.read_u8().await.unwrap() as usize];
            stream.read_exact(&mut username).await.unwrap();
            assert_eq!(username, b"fixture");
            let mut secret = vec![0; stream.read_u8().await.unwrap() as usize];
            stream.read_exact(&mut secret).await.unwrap();
            assert_eq!(secret, b"synthetic-password");
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 1, 0, 1]);
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let result = router.connect_tcp("203.0.113.1:443".parse().unwrap()).await;
        assert_eq!(result.is_ok(), accept);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn bad_replies_and_external_udp_relays_are_rejected() {
    for reply in [
        vec![4, 0, 0, 1, 127, 0, 0, 1, 1, 1],
        vec![5, 0, 1, 1, 127, 0, 0, 1, 1, 1],
        vec![5, 5, 0, 1, 127, 0, 0, 1, 1, 1],
        vec![5, 0, 0, 1, 192, 0, 2, 1, 1, 1],
        vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let router = Router::load(&config(listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = [0; 3];
            stream.read_exact(&mut hello).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&reply).await.unwrap();
        });
        assert!(
            router
                .associate("203.0.113.1:53".parse().unwrap())
                .await
                .is_err()
        );
        server.await.unwrap();
        assert_eq!(
            router
                .proxy
                .as_ref()
                .unwrap()
                .associations
                .available_permits(),
            1
        );
    }
}

#[test]
fn decoder_handles_bounded_arbitrary_input() {
    let target = "[2001:db8::1]:53".parse().unwrap();
    let mut seed = 1u64;
    for len in 0..512 {
        let mut bytes = vec![0; len];
        for _ in 0..32 {
            for byte in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed as u8;
            }
            let _ = socks5::decode_udp(&bytes, target);
        }
    }
}

#[tokio::test]
async fn packet_budget_drops_oversize_without_corrupting_next_datagram() {
    let proxy = mock::MockSocks::start().await;
    let mut c = config(proxy.addr);
    c.socks5.as_mut().unwrap().udp_max_packet_size = 4000;
    let router = Router::load(&c).unwrap();
    let (socket, association) = router
        .associate("203.0.113.1:53".parse().unwrap())
        .await
        .unwrap();
    let socket = UdpSocket::from_std(socket).unwrap();
    let mut packet = vec![1, 2, 3];
    assert!(!association.encode(&vec![0; 3991], &mut packet));
    assert!(packet.is_empty());
    let mut mapped = vec![0, 0, 0, 4];
    mapped.extend_from_slice(
        &"::ffff:203.0.113.1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    mapped.extend_from_slice(&53u16.to_be_bytes());
    mapped.resize(4012, 0);
    assert!(association.decode(&mapped).is_none());
    mapped.truncate(4000);
    assert_eq!(association.decode(&mapped).unwrap().len(), 3978);
    assert!(association.encode(b"still usable", &mut packet));
    socket.send(&packet).await.unwrap();
    let mut response = [0; 100];
    let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        association.decode(&response[..len]),
        Some(&b"still usable"[..])
    );
}

#[tokio::test]
async fn direct_reload_pins_existing_tcp_udp_and_pending_setup_snapshots() {
    let proxy = mock::MockSocks::start().await;
    let file = TempFile::new(b"192.0.2.0/24\n");
    let mut c = config(proxy.addr);
    c.direct_cidrs_file = Some(file.0.clone());
    let router = Router::load(&c).unwrap();
    let direct = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = direct.local_addr().unwrap();
    let old = router.snapshot();
    let mut existing = router.connect_tcp(target).await.unwrap();
    let (udp, association) = router.associate(target).await.unwrap();
    let udp = UdpSocket::from_std(udp).unwrap();
    std::fs::write(&file.0, "127.0.0.0/8\n2001:db9::/32\n").unwrap();
    router.install_direct_ranges(router.prepare_direct_reload().unwrap());
    assert_eq!(router.route(target.ip()), OutboundRoute::Direct);
    assert_eq!(
        router.route("2001:db9::1".parse().unwrap()),
        OutboundRoute::Direct
    );
    assert_eq!(
        router.route_snapshot(&old, target.ip()),
        OutboundRoute::Socks5
    );
    // Inline startup prefixes remain present.
    assert_eq!(
        router.route("2001:db8::1".parse().unwrap()),
        OutboundRoute::Direct
    );
    let mut pending = router.connect_tcp_snapshot(target, &old).await.unwrap();
    for stream in [&mut existing, &mut pending] {
        stream.write_all(b"old").await.unwrap();
        let mut bytes = [0; 3];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"old");
    }
    let mut wire = Vec::new();
    association.encode(b"old UDP", &mut wire);
    udp.send(&wire).await.unwrap();
    let mut bytes = [0; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), udp.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(association.decode(&bytes[..n]), Some(&b"old UDP"[..]));
    let _new = router.connect_tcp(target).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), direct.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(proxy.requests.lock().unwrap().len(), 3);
    let digest = router.files_digest();
    std::fs::write(&file.0, "invalid").unwrap();
    assert!(router.prepare_direct_reload().is_err());
    assert_eq!(router.files_digest(), digest);
    assert_eq!(router.route(target.ip()), OutboundRoute::Direct);
}

#[test]
fn direct_reload_does_not_read_password_and_rejects_missing_file() {
    let password = TempFile::new(b"original-secret");
    let file = TempFile::new(b"192.0.2.0/24\n");
    let mut c = config("127.0.0.1:1080".parse().unwrap());
    c.direct_cidrs_file = Some(file.0.clone());
    c.socks5.as_mut().unwrap().username = Some("test".into());
    c.socks5.as_mut().unwrap().password_file = Some(password.0.clone());
    let router = Router::load(&c).unwrap();
    std::fs::remove_file(&password.0).unwrap();
    std::fs::write(&file.0, "203.0.113.0/24\n").unwrap();
    router.install_direct_ranges(router.prepare_direct_reload().unwrap());
    assert_eq!(
        router.route("203.0.113.1".parse().unwrap()),
        OutboundRoute::Direct
    );
    std::fs::remove_file(&file.0).unwrap();
    assert!(router.prepare_direct_reload().is_err());
    assert!(
        Router::load(&OutboundSection::default())
            .unwrap()
            .prepare_direct_reload()
            .is_err()
    );
}

#[tokio::test]
async fn sized_udp_receive_buffer_preserves_boundaries_and_rejects_truncation() {
    use crate::tunnel::udp::{recv_buffer_size, recv_payload};

    let proxy = mock::MockSocks::start().await;
    assert_eq!(recv_buffer_size(None, 65507), 65530);
    for target in ["203.0.113.1:53", "[2001:db9::1]:53"] {
        for budget in [4000, 65507] {
            let mut c = config(proxy.addr);
            c.socks5.as_mut().unwrap().udp_max_packet_size = budget;
            let router = Router::load(&c).unwrap();
            let (_socket, association) = router.associate(target.parse().unwrap()).await.unwrap();
            assert_eq!(recv_buffer_size(Some(&association), 65507), budget + 1);
            assert_eq!(recv_buffer_size(Some(&association), 1350), 1373);
            if budget != 4000 {
                continue;
            }
            // A local sender allows malformed/oversized frames independently
            // of the encoder's outbound validation.
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender
                .connect(receiver.local_addr().unwrap())
                .await
                .unwrap();
            receiver
                .connect(sender.local_addr().unwrap())
                .await
                .unwrap();
            let mut buffer = vec![0; recv_buffer_size(Some(&association), 65507)];
            let mut header = Vec::new();
            assert!(association.encode(&[], &mut header));
            let mut headers = vec![header];
            if target.starts_with("203") {
                let mut mapped = vec![0, 0, 0, 4];
                mapped.extend_from_slice(
                    &"::ffff:203.0.113.1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets(),
                );
                mapped.extend_from_slice(&53u16.to_be_bytes());
                headers.push(mapped);
            }
            for header in headers {
                for size in [header.len(), 3999, 4000, 4001, 8000] {
                    let mut frame = header.clone();
                    frame.resize(size, 42);
                    sender.send(&frame).await.unwrap();
                    let mut marker = Vec::new();
                    assert!(association.encode(b"next", &mut marker));
                    // Oversized packets must be skipped, including a truncated
                    // prefix that would otherwise decode as a valid packet.
                    if size > budget {
                        sender.send(&marker).await.unwrap();
                    }
                    let len = tokio::time::timeout(
                        Duration::from_secs(2),
                        recv_payload(&receiver, Some(&association), &mut buffer),
                    )
                    .await
                    .unwrap()
                    .unwrap();
                    if size > budget {
                        assert_eq!(&buffer[..len], b"next");
                    } else {
                        assert_eq!(&buffer[..len], &frame[header.len()..]);
                    }
                }
            }
        }
    }
}
