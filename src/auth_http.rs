//! Bounded asynchronous HTTP authorization, independent of the packet path.
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use http::{Request, Uri};
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use ring::hmac;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, watch};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::{AuthBackend, AuthorizationSection, HttpAuthSection, ServerConfig};

const RESPONSE_LIMIT: usize = 4096;
const FLIGHT_LIMIT: usize = 256;
type Key = [u8; 32];
type Decision = Option<Uuid>;

pub(crate) fn validate_config(config: &ServerConfig) -> anyhow::Result<()> {
    let auth = &config.authorization;
    validate(auth)?;
    if auth.backend == AuthBackend::Http {
        ensure!(
            config.clients.is_empty(),
            "invalid configuration: authorization.backend = http forbids [[clients]]"
        );
        for listener in &config.listeners {
            let local = &listener.auth;
            ensure!(
                local.users.is_empty()
                    && local.username.is_empty()
                    && local.password_hash.is_empty()
                    && local.id.is_nil(),
                "invalid configuration: authorization.backend = http forbids file credentials (users, username, password_hash, id) on every listener, including disabled listeners"
            );
            if local.client_cert_enabled() {
                ensure!(
                    auth.http
                        .as_ref()
                        .and_then(|http| http.client_ca_path.as_ref())
                        .is_some(),
                    "invalid configuration: HTTP client_cert requires authorization.http.client_ca_path"
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn validate(auth: &AuthorizationSection) -> anyhow::Result<()> {
    if auth.backend == AuthBackend::File {
        ensure!(
            auth.http.is_none(),
            "invalid configuration: authorization.http requires backend = http"
        );
        return Ok(());
    }
    let cfg = auth
        .http
        .as_ref()
        .context("backend = http requires [authorization.http]")?;
    endpoint(cfg)?;
    ensure!(
        (10..=30000).contains(&cfg.timeout_ms),
        "HTTP auth timeout_ms must be 10..=30000"
    );
    ensure!(
        cfg.cache_ttl_secs <= 3600,
        "HTTP auth cache_ttl_secs must be 0..=3600"
    );
    ensure!(
        (1..=65536).contains(&cfg.cache_max_entries),
        "HTTP auth cache_max_entries must be 1..=65536"
    );
    ensure!(
        (1..=256).contains(&cfg.max_in_flight),
        "HTTP auth max_in_flight must be 1..=256"
    );
    Ok(())
}

pub(crate) fn shared(auth: &AuthorizationSection) -> anyhow::Result<Option<Arc<HttpAuth>>> {
    (auth.backend == AuthBackend::Http)
        .then(|| HttpAuth::new(auth))
        .transpose()
}

fn endpoint(cfg: &HttpAuthSection) -> anyhow::Result<Uri> {
    let uri: Uri = cfg.url.parse().context("invalid HTTP auth URL")?;
    ensure!(
        uri.scheme_str() == Some("http"),
        "HTTP auth URL must use http and a loopback IP literal"
    );
    let host = uri.host().context("HTTP auth URL needs a host")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let ip: IpAddr = host
        .parse()
        .context("HTTP auth host must be a loopback IP literal, not DNS")?;
    let loopback = match ip {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map_or_else(|| ip.is_loopback(), |ip| ip.is_loopback()),
    };
    ensure!(
        loopback && uri.port_u16().is_some_and(|p| p != 0),
        "HTTP auth URL requires a loopback IP and explicit nonzero port"
    );
    ensure!(
        uri.authority().is_some_and(|a| !a.as_str().contains('@')) && uri.query().is_none(),
        "HTTP auth URL cannot contain credentials or query parameters"
    );
    Ok(uri)
}

pub(crate) struct HttpAuth {
    client: Client<HttpConnector, Full<Bytes>>,
    uri: Uri,
    cfg: HttpAuthSection,
    key: hmac::Key,
    slots: Semaphore,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    cache: HashMap<Key, (Uuid, Instant)>,
    order: VecDeque<Key>,
    flights: HashMap<Key, watch::Sender<Option<Decision>>>,
}

pub(crate) struct Attempt {
    pub(crate) auth: Arc<HttpAuth>,
    key: Key,
    body: Zeroizing<Vec<u8>>,
}

struct FlightGuard {
    auth: Arc<HttpAuth>,
    key: Key,
    completed: bool,
}
impl Drop for FlightGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if let Some(sender) = self
            .auth
            .state
            .lock()
            .expect("HTTP auth state poisoned")
            .flights
            .remove(&self.key)
        {
            sender.send_replace(Some(None));
        }
    }
}

// Retain zeroization ownership while Hyper sends the request body.
struct SecretBody(Zeroizing<Vec<u8>>);
impl AsRef<[u8]> for SecretBody {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuthorizationRequest<'a> {
    Basic {
        username: &'a str,
        password: &'a str,
    },
    ClientCert {
        public_key: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationResponse {
    ok: bool,
    #[serde(default)]
    id: Option<Uuid>,
}

impl HttpAuth {
    pub(crate) fn invalidate(&self, id: Uuid) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.cache.retain(|_, (cached_id, _)| *cached_id != id);
        let State { cache, order, .. } = &mut *state;
        order.retain(|key| cache.contains_key(key));
        true
    }

    pub(crate) fn new(auth: &AuthorizationSection) -> anyhow::Result<Arc<Self>> {
        validate(auth)?;
        let cfg = auth
            .http
            .as_ref()
            .context("missing HTTP auth configuration")?
            .clone();
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_millis(cfg.timeout_ms)));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new())
            .pool_timer(TokioTimer::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(cfg.max_in_flight)
            .http1_max_buf_size(8192)
            .build(connector);
        let key = hmac::Key::generate(hmac::HMAC_SHA256, &ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("failed to generate HTTP auth cache key"))?;
        Ok(Arc::new(Self {
            uri: endpoint(&cfg)?,
            slots: Semaphore::new(cfg.max_in_flight),
            cfg,
            client,
            key,
            state: Mutex::new(State::default()),
        }))
    }

    pub(crate) fn basic(self: &Arc<Self>, username: &[u8], password: &[u8]) -> Option<Attempt> {
        let username = std::str::from_utf8(username).ok()?;
        crate::auth::check_username(username).ok()?;
        let password = std::str::from_utf8(password).ok()?;
        self.attempt(AuthorizationRequest::Basic { username, password })
    }
    pub(crate) fn certificate(self: &Arc<Self>, key: &[u8]) -> Option<Attempt> {
        self.attempt(AuthorizationRequest::ClientCert {
            public_key: STANDARD.encode(key),
        })
    }
    fn attempt(self: &Arc<Self>, request: AuthorizationRequest<'_>) -> Option<Attempt> {
        let body = Zeroizing::new(serde_json::to_vec(&request).ok()?);
        let key = hmac::sign(&self.key, &body).as_ref().try_into().ok()?;
        Some(Attempt {
            auth: Arc::clone(self),
            key,
            body,
        })
    }
}

impl Attempt {
    pub(crate) fn cached(&self) -> Decision {
        let state = self.auth.state.lock().expect("HTTP auth state poisoned");
        state
            .cache
            .get(&self.key)
            .and_then(|(id, expires)| (Instant::now() < *expires).then_some(*id))
    }
    pub(crate) async fn verify(self) -> Decision {
        let timeout = Duration::from_millis(self.auth.cfg.timeout_ms);
        tokio::time::timeout(timeout, self.verify_inner())
            .await
            .ok()
            .flatten()
    }
    async fn verify_inner(self) -> Decision {
        let follower = {
            let mut state = self.auth.state.lock().expect("HTTP auth state poisoned");
            if let Some((id, expires)) = state.cache.get(&self.key)
                && Instant::now() < *expires
            {
                return Some(*id);
            }
            if let Some(sender) = state.flights.get(&self.key) {
                Some(sender.subscribe())
            } else {
                if state.flights.len() >= FLIGHT_LIMIT {
                    return None;
                }
                let (sender, _) = watch::channel(None);
                state.flights.insert(self.key, sender);
                None
            }
        };
        if let Some(mut receiver) = follower {
            loop {
                if let Some(result) = *receiver.borrow_and_update() {
                    return result;
                }
                if receiver.changed().await.is_err() {
                    return None;
                }
            }
        }
        let mut guard = FlightGuard {
            auth: Arc::clone(&self.auth),
            key: self.key,
            completed: false,
        };
        let _slot = self.auth.slots.acquire().await.ok()?;
        let request = Request::post(self.auth.uri.clone())
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_owner(SecretBody(self.body))))
            .ok()?;
        let result = async {
            let response = self.auth.client.request(request).await.ok()?;
            if response.status() != http::StatusCode::OK {
                return None;
            }
            let body = Limited::new(response.into_body(), RESPONSE_LIMIT)
                .collect()
                .await
                .ok()?
                .to_bytes();
            let response: AuthorizationResponse = serde_json::from_slice(&body).ok()?;
            response.id.filter(|id| response.ok && !id.is_nil())
        }
        .await;
        let mut state = self.auth.state.lock().expect("HTTP auth state poisoned");
        if let Some(id) = result
            && self.auth.cfg.cache_ttl_secs > 0
        {
            // FIFO eviction is bounded; expiry is absolute and never extended by hits.
            if state.cache.remove(&self.key).is_some() {
                state.order.retain(|key| key != &self.key);
            }
            while state.cache.len() >= self.auth.cfg.cache_max_entries {
                if let Some(oldest) = state.order.pop_front() {
                    state.cache.remove(&oldest);
                }
            }
            state.cache.insert(
                self.key,
                (
                    id,
                    Instant::now() + Duration::from_secs(self.auth.cfg.cache_ttl_secs),
                ),
            );
            state.order.push_back(self.key);
        }
        if let Some(sender) = state.flights.remove(&self.key) {
            sender.send_replace(Some(result));
        }
        guard.completed = true;
        result
    }
}

#[cfg(test)]
#[path = "../tests/support/auth_server.rs"]
mod fixture;
#[cfg(test)]
mod tests {
    use super::*;
    use fixture::{AuthorizationServer, Reply};
    use std::sync::atomic::Ordering;
    fn config(authorizer: &AuthorizationServer) -> AuthorizationSection {
        AuthorizationSection {
            backend: AuthBackend::Http,
            http: Some(HttpAuthSection {
                url: authorizer.url(),
                ..Default::default()
            }),
        }
    }
    #[tokio::test]
    async fn invalidate_removes_all_credentials_for_uuid_but_keeps_other_users() {
        let id = Uuid::new_v4();
        let other = Uuid::new_v4();
        let authorizer = AuthorizationServer::start(move |request| {
            Reply::json(
                serde_json::json!({"ok": true, "id": if request["username"] == "bob" { other } else { id }}),
            )
        });
        let auth = HttpAuth::new(&config(&authorizer)).unwrap();
        for password in [b"first".as_slice(), b"second".as_slice()] {
            assert_eq!(
                auth.basic(b"alice", password).unwrap().verify().await,
                Some(id)
            );
        }
        assert_eq!(auth.certificate(b"key").unwrap().verify().await, Some(id));
        assert_eq!(
            auth.basic(b"bob", b"secret").unwrap().verify().await,
            Some(other)
        );
        assert!(auth.invalidate(id));
        assert_eq!(auth.basic(b"alice", b"first").unwrap().cached(), None);
        assert_eq!(auth.basic(b"alice", b"second").unwrap().cached(), None);
        assert_eq!(auth.certificate(b"key").unwrap().cached(), None);
        assert_eq!(auth.basic(b"bob", b"secret").unwrap().cached(), Some(other));
        let state = auth.state.lock().unwrap();
        assert_eq!(state.cache.len(), 1);
        assert_eq!(state.order.len(), 1);
    }

    #[tokio::test]
    async fn keepalive_cache_password_isolation_and_coalescing() {
        let id = Uuid::new_v4();
        let authorizer = AuthorizationServer::start(move |request| {
            assert_eq!(request["type"], "basic");
            let mut reply =
                Reply::json(serde_json::json!({"ok": request["password"] == "correct", "id": id}));
            reply.delay = Duration::from_millis(30);
            reply
        });
        let auth = HttpAuth::new(&config(&authorizer)).unwrap();
        let mut tasks = Vec::new();
        for _ in 0..16 {
            tasks.push(tokio::spawn(
                auth.basic(b"alice", b"correct").unwrap().verify(),
            ));
        }
        for task in tasks {
            assert_eq!(task.await.unwrap(), Some(id));
        }
        assert_eq!(authorizer.count(), 1);
        assert_eq!(auth.basic(b"alice", b"correct").unwrap().cached(), Some(id));
        assert_eq!(auth.basic(b"alice", b"wrong").unwrap().verify().await, None);
        assert_eq!(
            auth.basic(b"bob", b"correct").unwrap().verify().await,
            Some(id)
        );
        assert_eq!(authorizer.count(), 3);
        assert_eq!(authorizer.connections.load(Ordering::Relaxed), 1);
        assert_eq!(auth.basic(b"alice", b"wrong").unwrap().cached(), None);
    }
    #[tokio::test]
    async fn bounded_cache_expiry_and_disabled_cache() {
        let id = Uuid::new_v4();
        let authorizer = AuthorizationServer::start(move |_| {
            Reply::json(serde_json::json!({"ok":true,"id":id}))
        });
        let mut cfg = config(&authorizer);
        cfg.http.as_mut().unwrap().cache_max_entries = 1;
        let auth = HttpAuth::new(&cfg).unwrap();
        for name in [b"alice".as_slice(), b"bob".as_slice()] {
            assert_eq!(auth.basic(name, b"pw").unwrap().verify().await, Some(id));
        }
        assert!(auth.basic(b"alice", b"pw").unwrap().cached().is_none());
        {
            let mut state = auth.state.lock().unwrap();
            for (_, expires) in state.cache.values_mut() {
                *expires = Instant::now();
            }
        }
        assert!(auth.basic(b"bob", b"pw").unwrap().cached().is_none());
        assert_eq!(auth.basic(b"bob", b"pw").unwrap().verify().await, Some(id));
        cfg.http.as_mut().unwrap().cache_ttl_secs = 0;
        let uncached = HttpAuth::new(&cfg).unwrap();
        assert_eq!(
            uncached.basic(b"bob", b"pw").unwrap().verify().await,
            Some(id)
        );
        assert!(uncached.basic(b"bob", b"pw").unwrap().cached().is_none());
    }
    #[tokio::test]
    async fn failures_timeout_and_cancel_do_not_authorize_or_poison_flights() {
        let authorizer = AuthorizationServer::start(|request| {
            let mut reply = Reply::json(serde_json::json!({"ok":true,"id":Uuid::new_v4()}));
            match request["username"].as_str().unwrap() {
                "nil" => reply.body = serde_json::json!({"ok":true,"id":Uuid::nil()}).to_string(),
                "missing" => reply.body = "{\"ok\":true}".into(),
                "malformed" => reply.body = "broken".into(),
                "huge" => reply.body = " ".repeat(RESPONSE_LIMIT + 1),
                "redirect" => reply.status = 302,
                "slow" => reply.delay = Duration::from_millis(150),
                _ => (),
            }
            reply
        });
        let mut cfg = config(&authorizer);
        cfg.http.as_mut().unwrap().timeout_ms = 50;
        let auth = HttpAuth::new(&cfg).unwrap();
        for name in ["nil", "missing", "malformed", "huge", "redirect", "slow"] {
            assert!(
                auth.basic(name.as_bytes(), b"pw")
                    .unwrap()
                    .verify()
                    .await
                    .is_none(),
                "{name}"
            );
        }
        let task = tokio::spawn(auth.basic(b"slow", b"pw").unwrap().verify());
        tokio::time::sleep(Duration::from_millis(10)).await;
        task.abort();
        let _ = task.await;
        assert!(auth.state.lock().unwrap().flights.is_empty());
        assert!(
            auth.basic(b"valid", b"pw")
                .unwrap()
                .verify()
                .await
                .is_some()
        );
    }
    #[test]
    fn local_only_and_disjoint_configuration() {
        let mut auth = AuthorizationSection {
            backend: AuthBackend::Http,
            http: Some(HttpAuthSection::default()),
        };
        for url in [
            "http://example.com:80/auth",
            "http://192.0.2.1:80/auth",
            "https://127.0.0.1:80/auth",
            "http://127.0.0.1/auth",
            "http://127.0.0.1:80/auth?secret=x",
        ] {
            auth.http.as_mut().unwrap().url = url.into();
            assert!(validate(&auth).is_err());
        }
        auth.http.as_mut().unwrap().url = "http://[::1]:8080/auth".into();
        validate(&auth).unwrap();
    }
}

#[cfg(test)]
mod concurrency_tests {
    use super::fixture::{AuthorizationServer, Reply};
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn bounds_concurrency_and_reconnects_when_authorizer_closes_connections() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (a, p) = (active.clone(), peak.clone());
        let authorizer = AuthorizationServer::start(move |_| {
            let n = a.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(20));
            a.fetch_sub(1, Ordering::SeqCst);
            let mut reply = Reply::json(serde_json::json!({"ok":true,"id":Uuid::new_v4()}));
            reply.close = true;
            reply
        });
        let config = AuthorizationSection {
            backend: AuthBackend::Http,
            http: Some(HttpAuthSection {
                url: authorizer.url(),
                max_in_flight: 2,
                ..Default::default()
            }),
        };
        let auth = HttpAuth::new(&config).unwrap();
        let mut tasks = Vec::new();
        for n in 0..10 {
            tasks.push(tokio::spawn(
                auth.basic(format!("user-{n}").as_bytes(), b"pw")
                    .unwrap()
                    .verify(),
            ));
        }
        for task in tasks {
            assert!(task.await.unwrap().is_some());
        }
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert_eq!(authorizer.count(), 10);
        assert_eq!(authorizer.connections.load(Ordering::Relaxed), 10);
    }
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    use crate::config::{AuthMode, AuthSection, BasicUser, ClientEntry};

    fn http_config() -> ServerConfig {
        ServerConfig {
            authorization: AuthorizationSection {
                backend: AuthBackend::Http,
                http: Some(HttpAuthSection {
                    url: "http://127.0.0.1:9080/authorize".into(),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }
    }

    #[test]
    fn one_source_allows_both_methods_but_rejects_all_file_credentials() {
        let mut config = http_config();
        let mut certificate = config.listeners[0].clone();
        certificate.auth.mode = AuthMode::ClientCert;
        config.listeners.push(certificate);
        assert!(validate_config(&config).is_err());
        config.authorization.http.as_mut().unwrap().client_ca_path = Some("test-ca.pem".into());
        validate_config(&config).unwrap();
        for enabled in [true, false] {
            for local in [
                AuthSection {
                    enabled,
                    id: Uuid::new_v4(),
                    ..Default::default()
                },
                AuthSection {
                    enabled,
                    username: "alice".into(),
                    ..Default::default()
                },
                AuthSection {
                    enabled,
                    password_hash: "hash".into(),
                    ..Default::default()
                },
                AuthSection {
                    enabled,
                    users: vec![BasicUser::default()],
                    ..Default::default()
                },
            ] {
                config.listeners[0].auth = local;
                assert!(
                    validate_config(&config)
                        .unwrap_err()
                        .to_string()
                        .contains("invalid configuration")
                );
            }
        }
        config.listeners[0].auth = AuthSection::default();
        config.clients.push(ClientEntry::default());
        assert!(validate_config(&config).is_err());
        config.clients.clear();
        config.authorization.backend = AuthBackend::File;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn http_toml_rejects_even_empty_file_fields_and_listener_backend() {
        let valid = toml::to_string(&http_config()).unwrap();
        crate::config::parse_toml(&valid).unwrap();
        for field in [
            "id = '00000000-0000-0000-0000-000000000000'",
            "username = ''",
            "password_hash = ''",
            "users = []",
            "backend = 'http'",
        ] {
            let text = valid.replace("[listeners.auth]", &format!("[listeners.auth]\n{field}"));
            assert!(crate::config::parse_toml(&text).is_err(), "{field}");
        }
        assert!(crate::config::parse_toml(&format!("clients = []\n{valid}")).is_err());
    }
}
