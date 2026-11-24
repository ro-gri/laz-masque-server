//! Local tunnel cancellation. Registration happens after authorization only.
use std::collections::HashMap;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Default)]
struct Entries {
    next: u64,
    sessions: HashMap<u64, (Uuid, Weak<Signal>)>,
}

pub(crate) struct Sessions {
    entries: Mutex<Entries>,
    wake: watch::Sender<()>,
}
impl Default for Sessions {
    fn default() -> Self {
        Self {
            entries: Mutex::new(Entries::default()),
            wake: watch::channel(()).0,
        }
    }
}
struct Signal {
    cancelled: watch::Sender<bool>,
    finished: watch::Sender<Option<bool>>,
    failed: AtomicBool,
}

pub(crate) struct Session {
    registry: Arc<Sessions>,
    key: u64,
    signal: Arc<Signal>,
}
impl Sessions {
    pub(crate) fn register(self: &Arc<Self>, id: Uuid) -> Arc<Session> {
        let signal = Arc::new(Signal {
            cancelled: watch::channel(false).0,
            finished: watch::channel(None).0,
            failed: AtomicBool::new(false),
        });
        let mut entries = self.entries.lock().expect("session registry poisoned");
        let key = entries.next;
        entries.next = entries
            .next
            .checked_add(1)
            .expect("session sequence exhausted");
        entries.sessions.insert(key, (id, Arc::downgrade(&signal)));
        Arc::new(Session {
            registry: self.clone(),
            key,
            signal,
        })
    }
    pub(crate) fn subscribe(&self) -> watch::Receiver<()> {
        self.wake.subscribe()
    }
    // Signal every matching session before awaiting any individual completion.
    // Receivers retain only completion state, never the session itself.
    pub(crate) fn cancel(&self, id: Uuid) -> Result<Vec<watch::Receiver<Option<bool>>>, ()> {
        let entries = self.entries.lock().map_err(|_| ())?;
        let mut completions = Vec::new();
        for (credential, signal) in entries.sessions.values() {
            if *credential == id
                && let Some(signal) = signal.upgrade()
            {
                completions.push(signal.finished.subscribe());
                signal.cancelled.send_replace(true);
            }
        }
        drop(entries);
        self.wake.send_replace(());
        Ok(completions)
    }
}
impl Session {
    pub(crate) fn fail(&self) {
        self.signal.failed.store(true, Ordering::Relaxed);
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        *self.signal.cancelled.borrow()
    }
    pub(crate) async fn cancelled(&self) {
        let _ = self
            .signal
            .cancelled
            .subscribe()
            .wait_for(|cancelled| *cancelled)
            .await;
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(mut entries) = self.registry.entries.lock() {
            entries.sessions.remove(&self.key);
        }
        self.signal
            .finished
            .send_replace(Some(!self.signal.failed.load(Ordering::Relaxed)));
    }
}

pub(crate) async fn wait(completions: Vec<watch::Receiver<Option<bool>>>) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut success = true;
    for mut completion in completions {
        let completed = *completion.borrow();
        if let Some(ok) = completed {
            success &= ok;
            continue;
        }
        match tokio::time::timeout_at(deadline, completion.wait_for(Option::is_some)).await {
            Ok(Ok(result)) => success &= *result == Some(true),
            _ => success = false,
        }
    }
    success
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn kick_signals_all_matches_and_waits_for_release_without_touching_other_ids() {
        let sessions = Arc::new(Sessions::default());
        let id = Uuid::new_v4();
        let first = sessions.register(id);
        let second = sessions.register(id);
        let other = sessions.register(Uuid::new_v4());
        let pending = sessions.cancel(id).unwrap();
        assert!(first.is_cancelled());
        assert!(second.is_cancelled());
        assert!(!other.is_cancelled());
        let new_session = sessions.register(id);
        assert!(!new_session.is_cancelled());
        first.fail();
        drop(first);
        drop(second);
        assert!(!wait(pending).await);
        assert_eq!(sessions.entries.lock().unwrap().sessions.len(), 2);
        let pending = sessions.cancel(id).unwrap();
        drop(new_session);
        assert!(wait(pending).await);
        assert!(wait(sessions.cancel(Uuid::new_v4()).unwrap()).await);
    }

    #[tokio::test]
    async fn stuck_session_does_not_prevent_signalling_and_releasing_others() {
        let sessions = Arc::new(Sessions::default());
        let id = Uuid::new_v4();
        let stuck = sessions.register(id);
        let healthy = sessions.register(id);
        let pending = sessions.cancel(id).unwrap();
        assert!(healthy.is_cancelled());
        drop(healthy);
        assert!(!wait(pending).await);
        assert!(stuck.is_cancelled());
    }
}
