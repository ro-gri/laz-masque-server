//! Private, live configuration evidence. Only keyed fingerprints cross the
//! owner-only local socket; no credentials, paths or configuration are sent.
//! Request byte S reads status; R reloads only the startup DIRECT CIDR file.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use ring::{hmac, rand::SecureRandom as _};
use serde::{Deserialize, Serialize};

use crate::config::ServerConfig;

const MAX_RESPONSE: u64 = 16 * 1024;

#[derive(Clone, Serialize, Deserialize)]
struct Section {
    digest: [u8; 32],
    reloadable: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    version: String,
    key: [u8; 32],
    config_file: Option<[u8; 32]>,
    sections: BTreeMap<String, Section>,
}

pub(crate) struct LoadedConfig(Mutex<Snapshot>);

pub(crate) struct TlsFingerprints {
    pub identity: [u8; 32],
    pub ech: Option<[u8; 32]>,
}

impl LoadedConfig {
    pub(crate) fn new(
        config: &ServerConfig,
        path: Option<&Path>,
        tls: TlsFingerprints,
        outbound_files: [u8; 32],
    ) -> anyhow::Result<Self> {
        let mut key = [0; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| anyhow::anyhow!("cannot seed local status fingerprints"))?;
        let mut snapshot = Snapshot {
            version: env!("CARGO_PKG_VERSION").into(),
            key,
            config_file: None,
            sections: BTreeMap::new(),
        };
        snapshot.config_file = path
            .map(|path| file_digest(&snapshot.key, path))
            .transpose()?;
        snapshot.sections = sections(&snapshot.key, config, tls, Some(outbound_files))?;
        Ok(Self(Mutex::new(snapshot)))
    }

    /// Prepare evidence before any reload snapshot is changed. A failed reload
    /// leaves both effective configuration and evidence on the previous state.
    pub(crate) fn prepare_reload(
        &self,
        config: &ServerConfig,
        tls: TlsFingerprints,
    ) -> anyhow::Result<Snapshot> {
        let mut snapshot = self
            .0
            .lock()
            .expect("loaded configuration poisoned")
            .clone();
        for (name, section) in sections(&snapshot.key, config, tls, None)? {
            if section.reloadable {
                snapshot.sections.insert(name, section);
            }
        }
        Ok(snapshot)
    }

    pub(crate) fn commit_reload(&self, snapshot: Snapshot) {
        let mut current = self.0.lock().expect("loaded configuration poisoned");
        for (name, section) in snapshot.sections {
            if section.reloadable {
                current.sections.insert(name, section);
            }
        }
    }
    /// Publish only the outbound evidence and ranges. No file or TOML is read here.
    fn install_direct_reload(
        &self,
        router: &crate::outbound::Router,
        ranges: Arc<crate::outbound::DirectRanges>,
    ) -> anyhow::Result<bool> {
        let mut snapshot = self.0.lock().expect("loaded configuration poisoned");
        let mut value = serde_json::to_value(router.config())?;
        value["files_digest"] = serde_json::json!(ranges.files_digest);
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&value)?);
        let section = Section {
            digest: digest(&snapshot.key, &bytes),
            reloadable: false,
        };
        let changed = router.files_digest() != ranges.files_digest;
        router.install_direct_ranges(ranges);
        snapshot.sections.insert("outbound".into(), section);
        Ok(changed)
    }
}

fn digest(key: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes)
        .as_ref()
        .try_into()
        .unwrap()
}

fn file_digest(key: &[u8; 32], path: &Path) -> anyhow::Result<[u8; 32]> {
    let path = std::fs::canonicalize(path).context("configuration file cannot be resolved")?;
    Ok(digest(key, path.as_os_str().as_encoded_bytes()))
}

fn sections(
    key: &[u8; 32],
    config: &ServerConfig,
    tls: TlsFingerprints,
    outbound_files: Option<[u8; 32]>,
) -> anyhow::Result<BTreeMap<String, Section>> {
    let mut value = serde_json::to_value(config)?;
    let files = match outbound_files {
        Some(files) => files,
        None => crate::outbound::Router::load(&config.outbound)?.files_digest(),
    };
    value["outbound"]["files_digest"] = serde_json::json!(files);
    // Ignore disabled authentication material and the obsolete stealth switch.
    let credentials: Vec<_> = config.listeners.iter().map(|listener| {
        if listener.auth.basic_enabled() && !listener.auth.http_enabled(&config.authorization) {
            if listener.auth.users.is_empty() {
                serde_json::json!([{"id": listener.auth.id, "username": listener.auth.username, "password_hash": listener.auth.password_hash}])
            } else { serde_json::json!(listener.auth.users) }
        } else { serde_json::json!([]) }
    }).collect();
    for listener in value["listeners"].as_array_mut().unwrap() {
        let auth = listener["auth"].as_object_mut().unwrap();
        for field in ["id", "users", "username", "password_hash", "stealth"] {
            auth.remove(field);
        }
    }
    if !config.listeners.iter().any(|listener| {
        listener
            .auth
            .file_client_cert_enabled(&config.authorization)
    }) {
        value["clients"] = serde_json::json!([]);
    }
    value["basic_credentials"] = serde_json::json!(credentials);
    let mut http = serde_json::to_value(&config.authorization.http)?;
    if let Some(object) = http.as_object_mut() {
        object.remove("client_ca_path");
    }
    let authority = config
        .authorization
        .http
        .as_ref()
        .and_then(|http| http.client_ca_path.as_deref())
        .map(|path| {
            Ok::<_, anyhow::Error>(serde_json::json!({"path": path, "digest": digest(key,
                &std::fs::read(path).context("cannot read client CA for status fingerprint")?)}))
        })
        .transpose()?;
    value["authorization"]
        .as_object_mut()
        .unwrap()
        .remove("http");
    value["http_authorization"] = http;
    value["client_authorities"] = serde_json::json!(authority);

    value["tls_identity"] = serde_json::json!(tls.identity);
    if let Some(ech) = tls.ech {
        value["tls"]["ech_config_fingerprint"] = serde_json::json!(ech);
    }
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| {
            let bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
            Ok((
                name.clone(),
                Section {
                    digest: digest(key, &bytes),
                    reloadable: matches!(
                        name.as_str(),
                        "clients" | "basic_credentials" | "tls_identity" | "http_authorization"
                    ),
                },
            ))
        })
        .collect()
}

impl Snapshot {
    pub(crate) fn compare(
        &self,
        path: &Path,
        config: &ServerConfig,
        tls: TlsFingerprints,
    ) -> anyhow::Result<Vec<(String, &'static str)>> {
        anyhow::ensure!(
            self.version == env!("CARGO_PKG_VERSION"),
            "running version differs; configuration comparison unavailable"
        );
        anyhow::ensure!(
            self.config_file == Some(file_digest(&self.key, path)?),
            "selected file is not the running process's configuration file"
        );
        let disk = sections(&self.key, config, tls, None)?;
        anyhow::ensure!(
            self.sections.len() == disk.len(),
            "runtime status schema differs"
        );
        disk.into_iter()
            .map(|(name, section)| {
                let loaded = self
                    .sections
                    .get(&name)
                    .context("runtime status section missing")?;
                let state = if loaded.digest == section.digest {
                    "applied"
                } else if section.reloadable {
                    "reload required"
                } else {
                    "restart required"
                };
                Ok((name, state))
            })
            .collect()
    }
}

#[cfg(unix)]
mod socket {
    use super::*;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::path::PathBuf;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    pub struct StatusServer {
        task: tokio::task::JoinHandle<()>,
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl Drop for StatusServer {
        fn drop(&mut self) {
            self.task.abort();
            if std::fs::symlink_metadata(&self.path)
                .is_ok_and(|metadata| metadata.dev() == self.device && metadata.ino() == self.inode)
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    pub(crate) async fn start(
        path: &Path,
        state: Arc<LoadedConfig>,
        router: Arc<crate::outbound::Router>,
    ) -> anyhow::Result<StatusServer> {
        // SAFETY: geteuid takes no pointers and only returns the process identity.
        let uid = unsafe { libc::geteuid() };
        let parent = path
            .parent()
            .context("status socket needs a private parent directory")?;
        let metadata =
            std::fs::symlink_metadata(parent).context("status socket parent is unavailable")?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.uid() == uid && metadata.mode() & 0o077 == 0,
            "status socket parent must be an owner-only directory (0700)"
        );
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                anyhow::ensure!(
                    metadata.file_type().is_socket() && metadata.uid() == uid,
                    "refusing to replace a non-owned status socket"
                );
                match tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::UnixStream::connect(path),
                )
                .await
                {
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        std::fs::remove_file(path)?
                    }
                    _ => anyhow::bail!("status socket is already in use or unavailable"),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener =
            tokio::net::UnixListener::bind(path).context("cannot bind local status socket")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let metadata = std::fs::symlink_metadata(path)?;
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                // Fixed one-byte protocol, one peer and at most one file loader.
                // Slow or disconnected peers cannot enqueue unbounded blocking work.
                let request = tokio::time::timeout(Duration::from_secs(1), stream.read_u8()).await;
                let bytes = match request {
                    Ok(Ok(b'S')) => {
                        let snapshot = state.0.lock().expect("loaded configuration poisoned");
                        serde_json::to_vec(&*snapshot)
                            .expect("fixed runtime status schema serializes")
                    }
                    Ok(Ok(b'R')) => {
                        let loader = Arc::clone(&router);
                        let result =
                            tokio::task::spawn_blocking(move || loader.prepare_direct_reload())
                                .await;
                        let result = match result {
                            Ok(Ok(ranges)) => state.install_direct_reload(&router, ranges),
                            Ok(Err(error)) => Err(error),
                            Err(_) => Err(anyhow::anyhow!("DIRECT loader failed")),
                        };
                        match result {
                            Ok(changed) => {
                                tracing::info!(changed, "DIRECT CIDR reload completed");
                                if changed {
                                    b"updated\n".to_vec()
                                } else {
                                    b"unchanged\n".to_vec()
                                }
                            }
                            Err(error) => {
                                tracing::warn!(%error,
                                    "DIRECT CIDR reload rejected; previous routes retained"
                                );
                                b"error: DIRECT CIDR reload rejected; previous routes retained\n"
                                    .to_vec()
                            }
                        }
                    }
                    _ => b"error: unsupported local control request\n".to_vec(),
                };
                // One bounded writer, no spawned task or input buffer per peer.
                let _ =
                    tokio::time::timeout(Duration::from_secs(1), stream.write_all(&bytes)).await;
            }
        });
        Ok(StatusServer {
            task,
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(crate) async fn read(path: &Path) -> anyhow::Result<Snapshot> {
        use tokio::io::AsyncReadExt as _;
        let metadata =
            std::fs::symlink_metadata(path).context("no accessible local runtime status socket")?;
        anyhow::ensure!(
            metadata.file_type().is_socket() && metadata.mode() & 0o077 == 0,
            "runtime status socket is not private"
        );
        let mut stream = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::UnixStream::connect(path),
        )
        .await
        .context("runtime status connection timed out")?
        .context("runtime status process is unavailable")?;
        stream.write_all(b"S").await?;
        let mut bytes = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(1),
            stream.take(MAX_RESPONSE + 1).read_to_end(&mut bytes),
        )
        .await
        .context("runtime status read timed out")??;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_RESPONSE,
            "runtime status response exceeded limit"
        );
        serde_json::from_slice(&bytes).context("invalid runtime status response")
    }
    /// Reload only the running process's startup CIDR file. Never parse the disk config.
    pub async fn reload_direct_cidrs(path: &Path) -> anyhow::Result<String> {
        let metadata =
            std::fs::symlink_metadata(path).context("local control socket unavailable")?;
        anyhow::ensure!(
            metadata.file_type().is_socket() && metadata.mode() & 0o077 == 0,
            "local control socket is not private"
        );
        // SAFETY: geteuid has no arguments and does not mutate process state.
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            uid == 0 || metadata.uid() == uid,
            "local control socket has another owner"
        );
        let exchange = async {
            let mut stream = tokio::net::UnixStream::connect(path).await?;
            stream.write_all(b"R").await?;
            let mut bytes = Vec::new();
            stream.take(257).read_to_end(&mut bytes).await?;
            anyhow::ensure!(bytes.len() <= 256, "oversized local control response");
            match bytes.as_slice() {
                b"updated\n" => Ok("DIRECT CIDRs updated".to_owned()),
                b"unchanged\n" => Ok("DIRECT CIDRs unchanged".to_owned()),
                _ => anyhow::bail!(
                    "DIRECT CIDR reload rejected or unsupported; inspect the server log and CIDR file"
                ),
            }
        };
        tokio::time::timeout(Duration::from_secs(30), exchange)
            .await
            .context("reload response timed out; outcome unknown, retry the command")?
    }
}

#[cfg(unix)]
pub use socket::StatusServer;
#[cfg(unix)]
pub use socket::reload_direct_cidrs;
#[cfg(unix)]
pub(crate) use socket::{read, start};

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn credential_reload_cannot_overwrite_newer_direct_evidence() {
        struct File(std::path::PathBuf);
        impl Drop for File {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("masque-direct-evidence-{}-{nonce}", std::process::id());
        let file = File(std::env::temp_dir().join(name));
        std::fs::write(&file.0, "192.0.2.0/24\n").unwrap();
        let mut config = ServerConfig::default();
        config.outbound.direct_cidrs_file = Some(file.0.clone());
        let router = crate::outbound::Router::load(&config.outbound).unwrap();
        let tls = || TlsFingerprints {
            identity: [0; 32],
            ech: None,
        };
        let state = LoadedConfig::new(&config, None, tls(), router.files_digest()).unwrap();
        let stale = state.prepare_reload(&config, tls()).unwrap();
        std::fs::write(&file.0, "203.0.113.0/24\n").unwrap();
        assert!(
            state
                .install_direct_reload(&router, router.prepare_direct_reload().unwrap())
                .unwrap()
        );
        let expected = state.0.lock().unwrap().sections["outbound"].digest;
        state.commit_reload(stale);
        assert_eq!(
            state.0.lock().unwrap().sections["outbound"].digest,
            expected
        );
        let snapshot = state.0.lock().unwrap();
        let disk = sections(&snapshot.key, &config, tls(), None).unwrap();
        assert_eq!(
            snapshot.sections["outbound"].digest,
            disk["outbound"].digest
        );
    }
    #[test]
    fn http_settings_reload_but_ca_content_requires_restart() {
        struct File(std::path::PathBuf);
        impl Drop for File {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let file =
            File(std::env::temp_dir().join(format!("masque-ca-evidence-{}", uuid::Uuid::new_v4())));
        std::fs::write(&file.0, "first CA bytes").unwrap();
        let mut config = ServerConfig::default();
        config.listeners[0].auth.mode = crate::config::AuthMode::ClientCert;
        config.authorization.backend = crate::config::AuthBackend::Http;
        config.authorization.http = Some(crate::config::HttpAuthSection {
            url: "http://127.0.0.1:9080/authorize".into(),
            client_ca_path: Some(file.0.clone()),
            ..Default::default()
        });
        let router = crate::outbound::Router::load(&config.outbound).unwrap();
        let tls = || TlsFingerprints {
            identity: [0; 32],
            ech: None,
        };
        let loaded = LoadedConfig::new(&config, None, tls(), router.files_digest()).unwrap();
        let original = loaded.0.lock().unwrap().clone();
        config.authorization.http.as_mut().unwrap().url = "http://127.0.0.1:9081/authorize".into();
        std::fs::write(&file.0, "replacement CA bytes").unwrap();
        let disk = sections(&original.key, &config, tls(), None).unwrap();
        assert_ne!(
            disk["client_authorities"].digest,
            original.sections["client_authorities"].digest
        );
        assert!(!disk["client_authorities"].reloadable);
        assert!(disk["http_authorization"].reloadable);
        loaded.commit_reload(loaded.prepare_reload(&config, tls()).unwrap());
        let updated = loaded.0.lock().unwrap();
        assert_eq!(
            updated.sections["client_authorities"].digest,
            original.sections["client_authorities"].digest
        );
        assert_eq!(
            updated.sections["http_authorization"].digest,
            disk["http_authorization"].digest
        );
    }
}
