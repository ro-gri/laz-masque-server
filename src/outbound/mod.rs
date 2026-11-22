//! Immutable IP routing and bounded SOCKS5 setup. No target hostname reaches
//! the upstream: access policy and routing use the same resolved IP snapshot.
mod socks5;
#[cfg(test)]
mod tests;

use std::fmt::Write as _;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, ensure};
use ipnet::IpNet;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::config::{OutboundRoute, OutboundSection};
pub(crate) use socks5::UdpAssociation;

const MAX_CIDR_BYTES: usize = 8 * 1024 * 1024;
const MAX_CIDRS: usize = 100_000;

pub(crate) struct Router {
    default: OutboundRoute,
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
    proxy: Option<Proxy>,
    attempts: [AtomicU64; 4],
    /// Digest of exactly the external files used to construct this instance.
    pub(crate) files_digest: [u8; 32],
}

struct Proxy {
    endpoint: SocketAddr,
    credentials: Option<(String, Zeroizing<Vec<u8>>)>,
    connecting: Arc<Semaphore>,
    associations: Arc<Semaphore>,
    max_connecting: usize,
    max_associations: usize,
    udp_max_packet_size: usize,
}

fn read_bounded(path: &Path, max: usize) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    ensure!(path.is_absolute(), "outbound file paths must be absolute");
    let file =
        std::fs::File::open(path).map_err(|_| anyhow::anyhow!("cannot open outbound file"))?;
    ensure!(
        file.metadata()?.is_file(),
        "outbound input must be a regular file"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("cannot read outbound file"))?;
    ensure!(bytes.len() <= max, "outbound file exceeds size limit");
    Ok(bytes)
}

impl Router {
    pub(crate) fn load(config: &OutboundSection) -> anyhow::Result<Self> {
        ensure!(
            config.direct_cidrs.len() <= MAX_CIDRS,
            "too many outbound CIDRs"
        );
        let mut cidrs = config.direct_cidrs.clone();
        let mut digest = ring::digest::Context::new(&ring::digest::SHA256);
        if let Some(path) = &config.direct_cidrs_file {
            let bytes = read_bounded(path, MAX_CIDR_BYTES)?;
            digest.update(&(bytes.len() as u64).to_be_bytes());
            digest.update(&bytes);
            let text = std::str::from_utf8(&bytes).context("outbound CIDR file must be UTF-8")?;
            for line in text.lines() {
                let line = line.split('#').next().unwrap().trim();
                if !line.is_empty() {
                    ensure!(cidrs.len() < MAX_CIDRS, "too many outbound CIDRs");
                    cidrs.push(line.to_owned());
                }
            }
            ensure!(!cidrs.is_empty(), "outbound CIDR file must not be empty");
        }
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for (index, cidr) in cidrs.iter().enumerate() {
            let net: IpNet = cidr
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid outbound CIDR at index {index}"))?;
            match net {
                IpNet::V4(net) => v4.push((
                    u32::from(net.network()) as u128,
                    u32::from(net.broadcast()) as u128,
                )),
                IpNet::V6(net) => {
                    if net.prefix_len() >= 96
                        && let Some(ip) = net.network().to_ipv4_mapped()
                    {
                        let start = u32::from(ip) as u128;
                        v4.push((start, start + ((1u128 << (128 - net.prefix_len())) - 1)));
                    } else {
                        v6.push((u128::from(net.network()), u128::from(net.broadcast())));
                    }
                }
            }
        }
        let proxy = config
            .socks5
            .as_ref()
            .map(|config| {
                ensure!(
                    config.endpoint.ip().to_canonical().is_loopback()
                        && config.endpoint.port() != 0,
                    "SOCKS5 endpoint must be a concrete loopback address with nonzero port"
                );
                ensure!(
                    (1..=4096).contains(&config.max_connecting),
                    "SOCKS5 max_connecting must be 1..4096"
                );
                ensure!(
                    (1..=65536).contains(&config.max_udp_associations),
                    "SOCKS5 max_udp_associations must be 1..65536"
                );
                ensure!(
                    (23..=65_507).contains(&config.udp_max_packet_size),
                    "SOCKS5 udp_max_packet_size must be 23..65507"
                );
                let credentials = match (&config.username, &config.password_file) {
                    (None, None) => None,
                    (Some(username), Some(path)) => {
                        ensure!(
                            (1..=255).contains(&username.len()),
                            "SOCKS5 username must be 1..255 bytes"
                        );
                        let mut password = read_bounded(path, 257)?;
                        // Accept one terminal line ending from a secret file.
                        if password.last() == Some(&b'\n') {
                            password.pop();
                            if password.last() == Some(&b'\r') {
                                password.pop();
                            }
                        }
                        ensure!(
                            (1..=255).contains(&password.len()),
                            "SOCKS5 password must be 1..255 bytes"
                        );
                        digest.update(&(password.len() as u64).to_be_bytes());
                        digest.update(&password);
                        Some((username.clone(), password))
                    }
                    _ => anyhow::bail!(
                        "SOCKS5 username and password_file must be specified together"
                    ),
                };
                Ok::<_, anyhow::Error>(Proxy {
                    endpoint: config.endpoint,
                    max_connecting: config.max_connecting,
                    max_associations: config.max_udp_associations,
                    udp_max_packet_size: config.udp_max_packet_size,
                    credentials,
                    connecting: Arc::new(Semaphore::new(config.max_connecting)),
                    associations: Arc::new(Semaphore::new(config.max_udp_associations)),
                })
            })
            .transpose()?;
        ensure!(
            config.default_route != OutboundRoute::Socks5 || proxy.is_some(),
            "SOCKS5 default route requires outbound.socks5"
        );
        Ok(Self {
            default: config.default_route,
            attempts: std::array::from_fn(|_| AtomicU64::new(0)),
            v4: merge(v4),
            v6: merge(v6),
            proxy,
            files_digest: digest.finish().as_ref().try_into().unwrap(),
        })
    }

    pub(crate) fn route(&self, ip: IpAddr) -> OutboundRoute {
        let (ranges, value) = match ip.to_canonical() {
            IpAddr::V4(ip) => (&self.v4, u32::from(ip) as u128),
            IpAddr::V6(ip) => (&self.v6, u128::from(ip)),
        };
        let i = ranges.partition_point(|(start, _)| *start <= value);
        if i > 0 && value <= ranges[i - 1].1 {
            OutboundRoute::Direct
        } else {
            self.default
        }
    }

    pub(crate) fn record_attempt(&self, udp: bool, ip: IpAddr) {
        let index = usize::from(udp) * 2 + usize::from(self.route(ip) == OutboundRoute::Socks5);
        self.attempts[index].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn render_metrics(&self, out: &mut String) {
        out.push_str("# HELP masque_outbound_attempts_total Target address setup attempts, including retries.\n# TYPE masque_outbound_attempts_total counter\n");
        for (index, (protocol, route)) in [
            ("tcp", "direct"),
            ("tcp", "socks5"),
            ("udp", "direct"),
            ("udp", "socks5"),
        ]
        .into_iter()
        .enumerate()
        {
            writeln!(
                out,
                "masque_outbound_attempts_total{{protocol=\"{protocol}\",route=\"{route}\"}} {}",
                self.attempts[index].load(Ordering::Relaxed)
            )
            .unwrap();
        }
        let (connecting, associations) = self.proxy.as_ref().map_or((0, 0), |p| {
            (
                p.max_connecting - p.connecting.available_permits(),
                p.max_associations - p.associations.available_permits(),
            )
        });
        for (name, help, value) in [
            (
                "masque_socks5_connecting",
                "SOCKS5 handshakes currently holding capacity.",
                connecting,
            ),
            (
                "masque_socks5_udp_associations",
                "SOCKS5 UDP association slots in use, including setup.",
                associations,
            ),
        ] {
            writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
            )
            .unwrap();
        }
    }

    pub(crate) async fn connect_tcp(&self, target: SocketAddr) -> io::Result<TcpStream> {
        self.record_attempt(false, target.ip());
        if self.route(target.ip()) == OutboundRoute::Direct {
            return TcpStream::connect(target).await;
        }
        let proxy = self.proxy.as_ref().expect("validated SOCKS5 route");
        let _slot = proxy.connecting.acquire().await.map_err(io::Error::other)?;
        let mut stream = socks5::authenticate(proxy).await?;
        socks5::command(&mut stream, 1, target).await?;
        Ok(stream)
    }

    pub(crate) async fn associate(
        &self,
        target: SocketAddr,
    ) -> io::Result<(std::net::UdpSocket, Arc<UdpAssociation>)> {
        let proxy = self.proxy.as_ref().expect("validated SOCKS5 route");
        // Fail promptly under active-association pressure. Waiting for setup
        // capacity is bounded by the caller's original setup deadline.
        let active = Arc::clone(&proxy.associations)
            .try_acquire_owned()
            .map_err(|_| io::Error::other("SOCKS5 UDP association limit reached"))?;
        let _slot = proxy.connecting.acquire().await.map_err(io::Error::other)?;
        socks5::associate(proxy, target, active).await
    }
}

fn merge(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}
