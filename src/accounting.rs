//! Optional per-credential cumulative accounting. Entries never expire.
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use uuid::Uuid;

#[derive(Default)]
struct Counters {
    rx: AtomicU64,
    tx: AtomicU64,
    active: AtomicU64,
}

/// A stable counter reference, acquired once at tunnel setup, not per packet.
#[derive(Clone, Default)]
pub(crate) struct Usage(
    Option<Arc<Counters>>,
    Option<Arc<crate::kick_auth::Session>>,
);
impl Usage {
    pub(crate) fn kick_failed(&self) {
        if let Some(session) = &self.1 {
            session.fail();
        }
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.1
            .as_ref()
            .is_some_and(|session| session.is_cancelled())
    }
    pub(crate) async fn cancelled(&self) {
        match &self.1 {
            Some(session) => session.cancelled().await,
            None => std::future::pending().await,
        }
    }

    pub(crate) fn rx(&self, bytes: usize) {
        if let Some(c) = &self.0 {
            c.rx.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }
    pub(crate) fn tx(&self, bytes: usize) {
        if let Some(c) = &self.0 {
            c.tx.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }
    pub(crate) fn activate(&self) -> Online {
        if let Some(c) = &self.0 {
            c.active.fetch_add(1, Ordering::Relaxed);
        }
        Online(self.clone())
    }
}
#[derive(Default)]
pub(crate) struct Online(Usage);
impl Drop for Online {
    fn drop(&mut self) {
        if let Some(c) = &self.0.0 {
            c.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Default)]
struct Entries {
    index: HashMap<Uuid, Usage>,
    rows: Vec<(Uuid, Usage)>,
}
pub(crate) struct Accounting {
    pub(crate) instance_id: Uuid,
    enabled: bool,
    pub(crate) sessions: Arc<crate::kick_auth::Sessions>,
    entries: Mutex<Entries>,
}
impl Accounting {
    pub(crate) fn new(config: &crate::config::AccountingSection) -> Self {
        Self {
            instance_id: Uuid::new_v4(),
            enabled: config.listen_addr.is_some(),
            sessions: Arc::new(crate::kick_auth::Sessions::default()),
            entries: Mutex::new(Entries::default()),
        }
    }
    pub(crate) fn acquire(&self, id: Option<Uuid>) -> Usage {
        if !self.enabled {
            return Usage::default();
        }
        let Some(id) = id.filter(|id| !id.is_nil()) else {
            return Usage::default();
        };
        let mut entries = self.entries.lock().expect("accounting registry poisoned");
        if let Some(usage) = entries.index.get(&id) {
            return Usage(usage.0.clone(), Some(self.sessions.register(id)));
        }
        let usage = Usage(Some(Arc::new(Counters::default())), None);
        entries.index.insert(id, usage.clone());
        entries.rows.push((id, usage.clone()));
        Usage(usage.0, Some(self.sessions.register(id)))
    }
    pub(crate) fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("accounting registry poisoned")
            .rows
            .len()
    }
    // A fixed upper index excludes new entries during a scrape. Copy only one
    // bounded batch; never hold the registry lock across network I/O.
    pub(crate) fn batch(&self, start: usize, end: usize) -> Vec<Row> {
        let entries = self.entries.lock().expect("accounting registry poisoned");
        entries.rows[start..end]
            .iter()
            .map(|(id, usage)| {
                let c = usage.0.as_ref().expect("registered counters");
                Row {
                    id: *id,
                    rx_bytes: c.rx.load(Ordering::Relaxed),
                    tx_bytes: c.tx.load(Ordering::Relaxed),
                    online: c.active.load(Ordering::Relaxed) != 0,
                }
            })
            .collect()
    }
}
#[derive(Serialize)]
pub(crate) struct Row {
    pub(crate) id: Uuid,
    rx_bytes: u64,
    tx_bytes: u64,
    #[serde(skip)]
    pub(crate) online: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counters_survive_disconnect_and_new_credentials_without_eviction() {
        let accounting = Accounting::new(&crate::config::AccountingSection {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        });
        let id = Uuid::new_v4();
        let usage = accounting.acquire(Some(id));
        let first = usage.activate();
        let second = usage.activate();
        usage.rx(17);
        usage.tx(29);
        drop(first);
        assert!(accounting.batch(0, 1)[0].online);
        drop(second);
        drop(usage);
        for _ in 0..2048 {
            accounting.acquire(Some(Uuid::new_v4()));
        }
        let row = &accounting.batch(0, 1)[0];
        assert_eq!(
            (row.id, row.rx_bytes, row.tx_bytes, row.online),
            (id, 17, 29, false)
        );
        let again = accounting.acquire(Some(id));
        again.rx(3);
        assert_eq!(accounting.batch(0, 1)[0].rx_bytes, 20);
        assert_eq!(accounting.len(), 2049);
    }
    #[test]
    fn disabled_and_anonymous_accounting_do_not_allocate_entries() {
        let disabled = Accounting::new(&Default::default());
        disabled.acquire(Some(Uuid::new_v4())).rx(10);
        assert_eq!(disabled.len(), 0);
        let enabled = Accounting::new(&crate::config::AccountingSection {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        });
        enabled.acquire(None).rx(20);
        enabled.acquire(Some(Uuid::nil())).tx(20);
        assert_eq!(enabled.len(), 0);
        assert_ne!(disabled.instance_id, enabled.instance_id);
    }
    #[test]
    fn concurrent_tunnels_share_exact_totals_and_drop_online_guards() {
        let accounting = Arc::new(Accounting::new(&crate::config::AccountingSection {
            listen_addr: Some("127.0.0.1:0".parse().unwrap()),
        }));
        let id = Uuid::new_v4();
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let accounting = accounting.clone();
                std::thread::spawn(move || {
                    let usage = accounting.acquire(Some(id));
                    let _online = usage.activate();
                    for _ in 0..1000 {
                        usage.rx(7);
                        usage.tx(9);
                    }
                })
            })
            .collect();
        for task in tasks {
            task.join().unwrap();
        }
        let row = &accounting.batch(0, 1)[0];
        assert_eq!(
            (row.rx_bytes, row.tx_bytes, row.online),
            (56000, 72000, false)
        );
    }
}
