use super::*;
use masque::config::{OutboundRoute, Socks5Section};

#[path = "../support/socks5.rs"]
mod mock;

#[test]
fn socks5_http3_tcp_udp_native_and_capsules() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let proxy = runtime.block_on(mock::MockSocks::start());
    exercise(
        proxy.addr,
        "203.0.113.1:443".parse().unwrap(),
        "203.0.113.1:53".parse().unwrap(),
        false,
    );
    assert_eq!(proxy.requests.lock().unwrap().len(), 4);
}

#[test]
fn socks5_http3_kick_auth_closes_tcp_and_udp_native_and_capsules() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let proxy = runtime.block_on(mock::MockSocks::start());
    exercise(
        proxy.addr,
        "203.0.113.1:443".parse().unwrap(),
        "203.0.113.1:53".parse().unwrap(),
        true,
    );
}

fn exercise(endpoint: SocketAddr, tcp_target: SocketAddr, udp_target: SocketAddr, kick: bool) {
    let dir = TempDir::new("socks5-http3");
    let key = p256_key();
    let (cert, key) = write_pem(
        dir.path(),
        "server",
        &key,
        &self_signed(&key, Some("localhost")),
    );
    let mut config = ServerConfig::default();
    config.tls.cert_path = cert;
    config.tls.key_path = key;
    config.listeners[0].listen_addr = ephemeral_addr();
    config.listeners[0].shards = 1;
    config.listeners[0].auth.enabled = false;
    config.ip_proxy.enabled = false;
    config.tcp_proxy.allow_targets = vec!["203.0.113.0/24".into(), "127.0.0.0/8".into()];
    config.udp_proxy.allow_targets = config.tcp_proxy.allow_targets.clone();
    config.tcp_proxy.deny_targets.clear();
    config.udp_proxy.deny_targets.clear();
    config.outbound.default_route = OutboundRoute::Socks5;
    config.outbound.socks5 = Some(Socks5Section {
        endpoint,
        ..Default::default()
    });
    let id = uuid::Uuid::new_v4();
    if kick {
        config.listeners[0].auth = masque::config::AuthSection {
            id,
            username: "alice".into(),
            password_hash: masque::auth::hash_password(b"secret").unwrap(),
            ..Default::default()
        };
        config.accounting.listen_addr = Some(ephemeral_addr());
    }
    let (peers, _, stats) = spawn_server_endpoints(config);
    let peer = peers[0];
    for native in [false, true] {
        let mut client = Client::connect_with_transport(
            peer,
            None,
            None,
            false,
            "127.0.0.1".parse().unwrap(),
            native,
            262_144,
        )
        .unwrap();
        client.handshake(Duration::from_secs(5)).unwrap();
        client.init_h3().unwrap();
        let tcp = client
            .h3
            .as_mut()
            .unwrap()
            .send_request(
                &mut client.quic,
                &[
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":authority", tcp_target.to_string().as_bytes()),
                    quiche::h3::Header::new(b"proxy-authorization", b"Basic YWxpY2U6c2VjcmV0"),
                ],
                false,
            )
            .unwrap();
        assert_eq!(
            client.response_status(tcp, Duration::from_secs(5)).unwrap(),
            200
        );
        client
            .h3
            .as_mut()
            .unwrap()
            .send_body(&mut client.quic, tcp, b"TCP via SOCKS5", !kick)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut echoed = Vec::new();
        while echoed.len() < 14 {
            assert!(Instant::now() < deadline);
            client.drive().unwrap();
            while let Ok((id, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
                if id == tcp && matches!(event, quiche::h3::Event::Data) {
                    let mut buf = [0; 64];
                    while let Ok(len) =
                        client
                            .h3
                            .as_mut()
                            .unwrap()
                            .recv_body(&mut client.quic, tcp, &mut buf)
                    {
                        echoed.extend_from_slice(&buf[..len]);
                    }
                }
            }
        }
        assert_eq!(echoed, b"TCP via SOCKS5");
        let udp = client
            .h3
            .as_mut()
            .unwrap()
            .send_request(
                &mut client.quic,
                &[
                    quiche::h3::Header::new(b":method", b"CONNECT"),
                    quiche::h3::Header::new(b":protocol", b"connect-udp"),
                    quiche::h3::Header::new(b":scheme", b"https"),
                    quiche::h3::Header::new(b":authority", b"localhost"),
                    quiche::h3::Header::new(
                        b":path",
                        format!(
                            "/.well-known/masque/udp/{}/{}/",
                            udp_target.ip(),
                            udp_target.port()
                        )
                        .as_bytes(),
                    ),
                    quiche::h3::Header::new(b"capsule-protocol", b"?1"),
                    quiche::h3::Header::new(b"proxy-authorization", b"Basic YWxpY2U6c2VjcmV0"),
                ],
                false,
            )
            .unwrap();
        assert_eq!(
            client.response_status(udp, Duration::from_secs(5)).unwrap(),
            200
        );
        for payload in [vec![], vec![5; 64], vec![7; 1200]] {
            if native {
                client
                    .quic
                    .dgram_send(&DatagramHeader::new(udp).unwrap().encode(&payload))
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut buf = [0; 1500];
                loop {
                    client.drive().unwrap();
                    if let Ok(n) = client.quic.dgram_recv(&mut buf) {
                        let decoded = masque::datagram::decode_ref(&buf[..n]).unwrap();
                        assert_eq!(decoded.stream_id, udp);
                        assert_eq!(decoded.payload, payload);
                        break;
                    }
                    assert!(Instant::now() < deadline);
                }
            } else {
                let mut wire = Vec::new();
                masque::capsule::encoder::encode_datagram_context_zero(&payload, &mut wire);
                client
                    .h3
                    .as_mut()
                    .unwrap()
                    .send_body(&mut client.quic, udp, &wire, false)
                    .unwrap();
                assert_eq!(
                    client.capsules(udp, 1, Duration::from_secs(5)),
                    [CapsuleFrame::Datagram([&[0][..], &payload].concat())]
                );
            }
        }
        if kick {
            let stats = stats.unwrap();
            let before = accounting::wait(stats, |v| v["online"] == serde_json::json!([id]));
            assert_eq!(accounting::kick(stats, id), serde_json::json!({"ok": true}));
            let after = accounting::read(stats);
            assert_eq!(after["online"], serde_json::json!([]));
            assert_eq!(after["traffic"], before["traffic"]);
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut reset = std::collections::HashSet::new();
            while reset.len() < 2 {
                assert!(Instant::now() < deadline);
                client.drive().unwrap();
                while let Ok((stream, event)) = client.h3.as_mut().unwrap().poll(&mut client.quic) {
                    if matches!(event, quiche::h3::Event::Reset(_)) {
                        assert!(stream == tcp || stream == udp);
                        reset.insert(stream);
                    }
                }
            }
            assert!(!client.quic.is_closed());
        }
    }
}
