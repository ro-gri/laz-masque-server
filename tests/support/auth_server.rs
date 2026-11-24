//! Loopback-only HTTP fixture with observable connection reuse.
#![allow(dead_code)]
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

pub struct Reply {
    pub status: u16,
    pub body: String,
    pub delay: Duration,
    pub close: bool,
}
impl Reply {
    pub fn json(body: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            delay: Duration::ZERO,
            close: false,
        }
    }
}
pub struct AuthorizationServer {
    pub addr: SocketAddr,
    pub requests: Arc<AtomicUsize>,
    pub connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl AuthorizationServer {
    pub fn start(handler: impl Fn(serde_json::Value) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let handler = Arc::new(handler);
        let (s, r, c) = (stop.clone(), requests.clone(), connections.clone());
        let worker = std::thread::spawn(move || {
            let mut workers = Vec::new();
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        c.fetch_add(1, Ordering::Relaxed);
                        let (s, r, handler) = (s.clone(), r.clone(), handler.clone());
                        workers.push(std::thread::spawn(move || {
                            serve(socket, s, r, handler.as_ref())
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            addr,
            requests,
            connections,
            stop,
            worker: Some(worker),
        }
    }
    pub fn url(&self) -> String {
        format!("http://{}/authorize", self.addr)
    }
    pub fn count(&self) -> usize {
        self.requests.load(Ordering::Relaxed)
    }
}
impl Drop for AuthorizationServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn serve(
    socket: TcpStream,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    handler: &dyn Fn(serde_json::Value) -> Reply,
) {
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut reader = BufReader::new(socket);
    while !stop.load(Ordering::Relaxed) {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return,
        }
        assert!(
            line.starts_with("POST /authorize HTTP/1.1"),
            "unexpected fixture request"
        );
        let mut length = 0;
        loop {
            line.clear();
            if reader.read_line(&mut line).is_err() {
                return;
            }
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse::<usize>().unwrap();
            }
        }
        assert!(length <= 65536);
        let mut body = vec![0; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        requests.fetch_add(1, Ordering::Relaxed);
        let reply = handler(serde_json::from_slice(&body).unwrap());
        std::thread::sleep(reply.delay);
        let close = if reply.close { "close" } else { "keep-alive" };
        let response = format!(
            "HTTP/1.1 {} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {close}\r\n\r\n{}",
            reply.status,
            reply.body.len(),
            reply.body
        );
        if reader.get_mut().write_all(response.as_bytes()).is_err() || reply.close {
            return;
        }
    }
}

/// A CA and a P-256 leaf valid for TLS client authentication.
pub fn certificate_pair() -> (
    boring::x509::X509,
    boring::x509::X509,
    boring::pkey::PKey<boring::pkey::Private>,
) {
    use boring::{
        asn1::Asn1Time,
        bn::BigNum,
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::PKey,
        x509::{
            X509, X509NameBuilder,
            extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
        },
    };
    let key = || {
        PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap()
    };
    let ca_key = key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test client CA").unwrap();
    let name = name.build();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name).unwrap();
    ca.set_issuer_name(&name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();
    let leaf_key = key();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_subject_name(&name).unwrap();
    leaf.set_issuer_name(ca.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(7).unwrap())
        .unwrap();
    leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    leaf.append_extension(ExtendedKeyUsage::new().client_auth().build().unwrap())
        .unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    (ca, leaf.build(), leaf_key)
}
