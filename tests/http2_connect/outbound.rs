use super::*;
use masque::config::{OutboundRoute, Socks5Section};

#[path = "../support/socks5.rs"]
mod mock;

fn routed_config(files: &TestFiles, proxy: std::net::SocketAddr) -> ServerConfig {
    let mut config = http2_config(files);
    config.outbound.default_route = OutboundRoute::Socks5;
    config.outbound.socks5 = Some(Socks5Section {
        endpoint: proxy,
        ..Default::default()
    });
    config.tcp_proxy.allow_targets = vec!["0.0.0.0/0".into(), "::/0".into()];
    config.udp_proxy.allow_targets = config.tcp_proxy.allow_targets.clone();
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_tcp_and_udp_http2_use_checked_ips() {
    let files = TestFiles::new();
    let proxy = mock::MockSocks::start().await;
    let (addr, server) = spawn_http2_config(routed_config(&files, proxy.addr)).await;
    let (mut client, driver) = connect_h2(addr).await;
    for destination in ["203.0.113.1:443", "[2001:db9::1]:443"] {
        let (response, mut send) = client
            .send_request(connect_request(destination.parse().unwrap()), false)
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        send.send_data(Bytes::from_static(b"SOCKS5 TCP"), true)
            .unwrap();
        let mut body = response.into_body();
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), async {
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                data.extend_from_slice(&chunk);
                body.flow_control().release_capacity(chunk.len()).unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(data, b"SOCKS5 TCP");
    }
    let request = super::udp_capsules::udp_request("203.0.113.1:53".parse().unwrap());
    let (response, mut send) = client.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    for payload in [vec![], vec![7; 64], vec![9; 1200]] {
        let mut wire = Vec::new();
        encoder::encode_datagram_context_zero(&payload, &mut wire);
        send.send_data(Bytes::from(wire), false).unwrap();
        let mut decoder = CapsuleDecoder::new();
        let frames = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let chunk = body.data().await.unwrap().unwrap();
                body.flow_control().release_capacity(chunk.len()).unwrap();
                let frames = decoder.decode(&chunk).unwrap();
                if !frames.is_empty() {
                    break frames;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            frames,
            [CapsuleFrame::Datagram([&[0][..], &payload].concat())]
        );
    }
    // A burst exercises multi-packet upstream reads and capsule boundaries.
    let mut wire = Vec::new();
    for tag in 0..32u8 {
        encoder::encode_datagram_context_zero(&[tag; 64], &mut wire);
    }
    send.send_data(Bytes::from(wire), false).unwrap();
    let mut decoder = CapsuleDecoder::new();
    let frames = tokio::time::timeout(Duration::from_secs(3), async {
        let mut frames = Vec::new();
        while frames.len() < 32 {
            let chunk = body.data().await.unwrap().unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
            frames.extend(decoder.decode(&chunk).unwrap());
        }
        frames
    })
    .await
    .unwrap();
    let expected: Vec<_> = (0..32u8)
        .map(|tag| CapsuleFrame::Datagram([&[0][..], &[tag; 64]].concat()))
        .collect();
    assert_eq!(frames, expected);
    assert_eq!(proxy.requests.lock().unwrap().len(), 3);
    drop(proxy);
    let closed = tokio::time::timeout(Duration::from_secs(3), body.data())
        .await
        .unwrap();
    assert!(closed.is_none() || closed.unwrap().is_err());
    server.abort();
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_http2_policy_denial_and_failure_do_not_contact_direct_target() {
    let files = TestFiles::new();
    let proxy = mock::MockSocks::start().await;
    let mut config = routed_config(&files, proxy.addr);
    config.tcp_proxy.deny_targets = vec!["203.0.113.0/24".into()];
    config.udp_proxy.deny_targets = config.tcp_proxy.deny_targets.clone();
    let (addr, server) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(addr).await;
    let (response, _) = client
        .send_request(connect_request("203.0.113.1:443".parse().unwrap()), false)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::FORBIDDEN);
    let (response, _) = client
        .send_request(
            super::udp_capsules::udp_request("203.0.113.1:53".parse().unwrap()),
            false,
        )
        .unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::FORBIDDEN);
    assert!(proxy.requests.lock().unwrap().is_empty());
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    drop(proxy);
    tokio::task::yield_now().await;
    let (response, _) = client
        .send_request(connect_request(target.local_addr().unwrap()), false)
        .unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), target.accept())
            .await
            .is_err()
    );
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (response, _) = client
        .send_request(
            super::udp_capsules::udp_request(udp.local_addr().unwrap()),
            false,
        )
        .unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::BAD_GATEWAY);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), udp.recv(&mut [0; 64]))
            .await
            .is_err()
    );
    server.abort();
    driver.abort();
}

/// Run with scripts/test-hysteria.py; ordinary tests use the deterministic peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an isolated Hysteria2 client/server pair"]
async fn hysteria2_real_tcp_udp_roundtrips() {
    let endpoint = std::env::var("MASQUE_TEST_HYSTERIA_SOCKS")
        .expect("use scripts/test-hysteria.py")
        .parse()
        .unwrap();
    let files = TestFiles::new();
    let mut config = routed_config(&files, endpoint);
    config.outbound.socks5.as_mut().unwrap().udp_max_packet_size = 4000;
    let (addr, server) = spawn_http2_config(config).await;
    let (mut client, driver) = connect_h2(addr).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_task = tokio::spawn(async move {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut received = [0; b"real Hysteria TCP".len()];
        socket.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"real Hysteria TCP");
        socket.write_all(&received).await.unwrap();
    });
    let (response, mut send) = client
        .send_request(connect_request(target_addr), false)
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut tcp_body = response.into_body();
    send.send_data(Bytes::from_static(b"real Hysteria TCP"), false)
        .unwrap();
    let mut echoed = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(chunk) = tcp_body.data().await {
            let chunk = chunk.unwrap();
            echoed.extend_from_slice(&chunk);
            tcp_body
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
        }
    })
    .await
    .unwrap();
    assert_eq!(echoed, b"real Hysteria TCP");
    tokio::time::timeout(Duration::from_secs(5), target_task)
        .await
        .unwrap()
        .unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (response, mut send) = client
        .send_request(
            super::udp_capsules::udp_request(udp.local_addr().unwrap()),
            false,
        )
        .unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    for len in [64, 1200, 3990] {
        eprintln!("Hysteria UDP payload: {len}");
        let payload = vec![0x5a; len];
        let mut wire = Vec::new();
        encoder::encode_datagram_context_zero(&payload, &mut wire);
        send.send_data(Bytes::from(wire), false).unwrap();
        super::udp_capsules::assert_echo(&udp, &mut body, &payload).await;
    }
    server.abort();
    driver.abort();
}
