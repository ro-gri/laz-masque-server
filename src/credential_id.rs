//! Stable credential IDs shared across transports, never across auth methods.
use std::collections::{HashMap, HashSet};

use anyhow::{Context, ensure};
use uuid::Uuid;

use crate::config::ServerConfig;

#[derive(PartialEq, Eq)]
enum Credential {
    Basic(String),
    Certificate(Vec<u8>),
}

/// Validate identities before startup or committing a reload. A Basic ID may
/// recur on different listeners with the same username (hashes may differ
/// during password rotation), but may not identify a second username or key.
pub(crate) fn validate(config: &ServerConfig) -> anyhow::Result<()> {
    crate::auth_http::validate_config(config)?;
    let mut identities = HashMap::new();
    for listener in &config.listeners {
        if !listener.auth.basic_enabled() || listener.auth.http_enabled(&config.authorization) {
            continue;
        }
        let auth = &listener.auth;
        let entries = if auth.users.is_empty() {
            vec![(auth.id, auth.username.as_str())]
        } else {
            ensure!(
                auth.id.is_nil(),
                "use users[].id instead of listeners.auth.id with users tables"
            );
            auth.users
                .iter()
                .map(|user| (user.id, user.username.as_str()))
                .collect()
        };
        let mut seen = HashSet::new();
        for (id, username) in entries {
            ensure!(
                seen.insert(id),
                "duplicate credential id on one Basic listener"
            );
            register(&mut identities, id, Credential::Basic(username.to_owned()))?;
        }
    }
    for client in config.clients.iter().filter(|_| {
        config
            .listeners
            .iter()
            .any(|l| l.auth.file_client_cert_enabled(&config.authorization))
    }) {
        let key = crate::client_identity::parse_public_key(&client.public_key)
            .context("invalid certificate credential public key")?;
        register(&mut identities, client.id, Credential::Certificate(key))?;
    }
    Ok(())
}

fn register(
    ids: &mut HashMap<Uuid, Credential>,
    id: Uuid,
    credential: Credential,
) -> anyhow::Result<()> {
    ensure!(
        !id.is_nil(),
        "credential id is required and must be a non-nil UUID; add id to the existing credential configuration"
    );
    if let Some(previous) = ids.get(&id) {
        ensure!(
            previous == &credential,
            "credential id is assigned to different credentials"
        );
    } else {
        ids.insert(id, credential);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BasicUser, ListenerTransport};

    fn config() -> ServerConfig {
        let mut config = ServerConfig::default();
        config.listeners[0].auth.users = vec![BasicUser {
            id: Uuid::new_v4(),
            username: "alice".into(),
            password_hash: "hash".into(),
        }];
        config
    }

    #[test]
    fn same_credential_can_span_transports_but_not_alias_other_credentials() {
        let mut config = config();
        let mut h2 = config.listeners[0].clone();
        h2.transport = ListenerTransport::Http2;
        config.listeners.push(h2);
        validate(&config).unwrap();
        config.listeners[1].auth.users[0].username = "bob".into();
        assert!(validate(&config).is_err());
        config.listeners[1].auth.users[0].id = Uuid::new_v4();
        validate(&config).unwrap();
        let duplicate = config.listeners[0].auth.users[0].clone();
        config.listeners[0].auth.users.push(duplicate);
        assert!(validate(&config).is_err());
    }

    #[test]
    fn missing_nil_and_malformed_ids_are_rejected_and_roundtrip_is_typed() {
        let mut config = config();
        let encoded = toml::to_string(&config).unwrap();
        let decoded = crate::config::parse_toml(&encoded).unwrap();
        assert_eq!(decoded, config);
        let id = config.listeners[0].auth.users[0].id;
        assert!(
            crate::config::parse_toml(&encoded.replace(&id.to_string(), "not-a-uuid")).is_err()
        );
        let missing = encoded
            .lines()
            .filter(|line| !line.starts_with("id ="))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(validate(&crate::config::parse_toml(&missing).unwrap()).is_err());
        config.listeners[0].auth.users[0].id = Uuid::nil();
        assert!(validate(&config).is_err());
        config.listeners[0].auth.enabled = false;
        validate(&config).unwrap();
    }

    #[test]
    fn certificate_id_cannot_alias_a_basic_credential() {
        let mut ids = HashMap::new();
        let id = Uuid::new_v4();
        register(&mut ids, id, Credential::Basic("alice".into())).unwrap();
        assert!(register(&mut ids, id, Credential::Certificate(vec![1])).is_err());
        let cert_id = Uuid::new_v4();
        register(&mut ids, cert_id, Credential::Certificate(vec![1])).unwrap();
        assert!(register(&mut ids, cert_id, Credential::Certificate(vec![2])).is_err());
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;
    use crate::config::{AuthMode, ClientEntry};

    #[test]
    fn certificate_ids_are_required_and_cannot_be_shared_by_different_keys() {
        let mut config = ServerConfig::default();
        config.listeners[0].auth.mode = AuthMode::ClientCert;
        config.clients.push(ClientEntry {
            public_key: crate::enroll::generate_client_key()
                .unwrap()
                .public_key_b64
                .clone(),
            ..Default::default()
        });
        assert!(validate(&config).is_err());
        config.clients[0].id = Uuid::new_v4();
        validate(&config).unwrap();
        let mut other = config.clients[0].clone();
        other.public_key = crate::enroll::generate_client_key()
            .unwrap()
            .public_key_b64
            .clone();
        config.clients.push(other);
        assert!(validate(&config).is_err());
    }
}
