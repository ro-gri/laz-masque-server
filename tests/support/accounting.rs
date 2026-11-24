use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub fn read(addr: SocketAddr) -> serde_json::Value {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .write_all(b"GET /stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}
pub fn wait(addr: SocketAddr, predicate: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let value = read(addr);
        if predicate(&value) {
            return value;
        }
        assert!(Instant::now() < deadline, "last statistics: {value}");
        std::thread::sleep(Duration::from_millis(10));
    }
}
