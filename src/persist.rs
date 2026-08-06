//! The disk tier of the cache.
//!
//! Memory holds what is hot; this holds everything. Eviction is a memory
//! concern -- a definition pushed out of the map is still on disk, and reading
//! it back costs a page fault rather than a round trip to an upstream that
//! stalls on 40% of cold requests. Nothing is ever evicted here; entries leave
//! only when they expire.
//!
//! That split is why this is a real embedded database and not the obvious
//! append-only log. A log has to be indexed to be read from at random, and an
//! in-memory index over every key on disk reintroduces exactly the memory
//! ceiling the split exists to escape -- smaller by a constant, unbounded all
//! the same. redb keeps its B-tree on disk and its page cache bounded, so the
//! process footprint stops depending on how much has ever been cached.
//!
//! Writes are batched onto one background thread. Each is ~0.4KB and arrives on
//! a cache miss, so committing per entry would fsync once per upstream fetch to
//! save work that a crash makes us redo anyway. Losing the last batch costs a
//! re-fetch, which is the thing this is a cache for.

use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const DEFINITIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("definitions");

/// How many queued writes are folded into one transaction.
const BATCH: usize = 512;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A stored value and when it stops being one.
#[derive(Serialize, Deserialize)]
struct Record<V> {
    /// Absolute Unix expiry, not a TTL. The point of persisting is to survive a
    /// process that is not running, and a duration relative to insertion is
    /// meaningless once nobody is left to remember when insertion was.
    e: u64,
    v: V,
}

enum Msg {
    Put(String, Vec<u8>),
    /// Delete everything expired. Nothing else removes entries, so without this
    /// the file only grows.
    Sweep,
    Shutdown,
}

pub struct Store<V> {
    db: Arc<Database>,
    tx: Sender<Msg>,
    /// Taken by whichever call to `shutdown` gets there first. Behind a lock
    /// because the store lives in shared state and shutdown only borrows it.
    writer: std::sync::Mutex<Option<JoinHandle<()>>>,
    _marker: std::marker::PhantomData<fn() -> V>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<V: Serialize + DeserializeOwned> Store<V> {
    pub fn open(path: &Path) -> Result<Self, Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Arc::new(Database::create(path)?);

        // Creating the table up front means every later read can open it rather
        // than handling "no table yet" as a distinct case.
        let txn = db.begin_write()?;
        txn.open_table(DEFINITIONS)?;
        txn.commit()?;

        let (tx, rx) = mpsc::channel();
        let writer_db = db.clone();
        let writer = std::thread::Builder::new()
            .name("cache-writer".into())
            .spawn(move || run_writer(writer_db, rx))?;

        Ok(Self {
            db,
            tx,
            writer: std::sync::Mutex::new(Some(writer)),
            _marker: std::marker::PhantomData,
        })
    }

    /// The value and the TTL it has left, or `None` if absent or expired.
    ///
    /// Blocking. Callers on an async runtime must run it on a blocking thread:
    /// a warm read is a page-cache hit but a cold one is a disk seek.
    pub fn get(&self, key: &str) -> Option<(V, Duration)> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(DEFINITIONS).ok()?;
        let bytes = table.get(key).ok()??;
        let record: Record<V> = serde_json::from_slice(bytes.value()).ok()?;
        let now = unix_now();
        if record.e <= now {
            // Left for the sweep rather than deleted here: a read should not
            // need a write transaction, and the entry is already invisible.
            return None;
        }
        Some((record.v, Duration::from_secs(record.e - now)))
    }

    /// Queue a write. Never blocks the caller on disk.
    pub fn put(&self, key: &str, value: &V, ttl: Duration) {
        let record = Record {
            e: unix_now() + ttl.as_secs(),
            v: value,
        };
        if let Ok(bytes) = serde_json::to_vec(&record) {
            let _ = self.tx.send(Msg::Put(key.to_owned(), bytes));
        }
    }

    pub fn sweep(&self) {
        let _ = self.tx.send(Msg::Sweep);
    }

    pub fn len(&self) -> u64 {
        self.db
            .begin_read()
            .ok()
            .and_then(|txn| txn.open_table(DEFINITIONS).ok())
            .and_then(|t| t.len().ok())
            .unwrap_or(0)
    }

    /// Flush queued writes and stop the writer. Idempotent, and implied by
    /// dropping the store -- explicit at shutdown only so a clean stop waits
    /// for the queue rather than racing the process exit.
    pub fn shutdown(&self) {
        let _ = self.tx.send(Msg::Shutdown);
        let handle = self.writer.lock().ok().and_then(|mut w| w.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl<V> Drop for Store<V> {
    fn drop(&mut self) {
        // The writer holds a clone of the database handle, and redb keeps the
        // file locked until the last one goes. Joining here is what makes the
        // path reusable -- by a test, or by a process that reopens it.
        let _ = self.tx.send(Msg::Shutdown);
        let handle = self.writer.lock().ok().and_then(|mut w| w.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

fn run_writer(db: Arc<Database>, rx: Receiver<Msg>) {
    let mut pending: Vec<(String, Vec<u8>)> = Vec::new();

    loop {
        let Ok(msg) = rx.recv() else { break };
        match msg {
            Msg::Put(key, bytes) => {
                pending.push((key, bytes));
                // Take whatever else is already queued, so a burst of misses
                // costs one transaction rather than one each.
                while pending.len() < BATCH {
                    match rx.try_recv() {
                        Ok(Msg::Put(k, b)) => pending.push((k, b)),
                        Ok(Msg::Sweep) => {
                            commit(&db, &mut pending);
                            sweep(&db);
                        }
                        Ok(Msg::Shutdown) => {
                            commit(&db, &mut pending);
                            return;
                        }
                        Err(_) => break,
                    }
                }
                commit(&db, &mut pending);
            }
            Msg::Sweep => sweep(&db),
            Msg::Shutdown => break,
        }
    }
    commit(&db, &mut pending);
}

fn commit(db: &Database, pending: &mut Vec<(String, Vec<u8>)>) {
    if pending.is_empty() {
        return;
    }
    let result = (|| -> Result<(), Error> {
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(DEFINITIONS)?;
            for (key, bytes) in pending.iter() {
                table.insert(key.as_str(), bytes.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    })();
    if let Err(e) = result {
        // A failed write costs a re-fetch later. Nothing to recover, but a
        // silently read-only cache is worth knowing about.
        eprintln!("cache: could not persist {} entries: {e}", pending.len());
    }
    pending.clear();
}

fn sweep(db: &Database) {
    let now = unix_now();
    let expired = (|| -> Result<Vec<String>, Error> {
        let txn = db.begin_read()?;
        let table = txn.open_table(DEFINITIONS)?;
        let mut expired = Vec::new();
        for row in table.iter()? {
            let (key, value) = row?;
            // Only the expiry is needed, and it is the first field, so the
            // definition itself is never deserialised during a sweep.
            if let Ok(head) = serde_json::from_slice::<Expiry>(value.value()) {
                if head.e <= now {
                    expired.push(key.value().to_owned());
                }
            }
        }
        Ok(expired)
    })();

    let Ok(expired) = expired else { return };
    if expired.is_empty() {
        return;
    }
    let result = (|| -> Result<(), Error> {
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(DEFINITIONS)?;
            for key in &expired {
                table.remove(key.as_str())?;
            }
        }
        txn.commit()?;
        Ok(())
    })();
    match result {
        Ok(()) => eprintln!("cache: swept {} expired entries", expired.len()),
        Err(e) => eprintln!("cache: sweep failed: {e}"),
    }
}

/// Just the expiry, for sweeping without paying to parse the value.
#[derive(Deserialize)]
struct Expiry {
    e: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_path() -> PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "clearly-cached-test-{}-{}/definitions.redb",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    /// Close one store and reopen the same file, the way a restart would.
    fn restart(store: Store<String>, path: &Path) -> Store<String> {
        drop(store); // Releases redb's file lock once the writer has joined.
        Store::<String>::open(path).unwrap()
    }

    #[test]
    fn survives_a_restart() {
        let path = temp_path();
        let store = Store::<String>::open(&path).unwrap();
        store.put(
            "npm/npmjs/-/lodash/4.17.21",
            &"MIT".into(),
            Duration::from_secs(600),
        );

        let store = restart(store, &path);
        let (value, ttl) = store.get("npm/npmjs/-/lodash/4.17.21").unwrap();
        assert_eq!(value, "MIT");
        // Remaining, not original: a restart must not extend the life of an
        // entry that was nearly expired when it was written.
        assert!(ttl <= Duration::from_secs(600));
    }

    #[test]
    fn an_expired_entry_is_not_returned() {
        let path = temp_path();
        let store = Store::<String>::open(&path).unwrap();
        store.put("stale", &"x".into(), Duration::from_secs(0));
        store.put("fresh", &"y".into(), Duration::from_secs(600));

        let store = restart(store, &path);
        assert!(store.get("stale").is_none());
        assert!(store.get("fresh").is_some());
    }

    #[test]
    fn sweeping_removes_expired_entries_and_keeps_live_ones() {
        let path = temp_path();
        let store = Store::<String>::open(&path).unwrap();
        for i in 0..10 {
            store.put(&format!("stale{i}"), &"x".into(), Duration::from_secs(0));
        }
        store.put("live", &"y".into(), Duration::from_secs(600));
        store.sweep();

        let store = restart(store, &path);
        assert_eq!(store.len(), 1, "expired entries were not swept");
        assert!(store.get("live").is_some());
    }

    #[test]
    fn a_repeated_key_keeps_the_later_value() {
        let path = temp_path();
        let store = Store::<String>::open(&path).unwrap();
        store.put("k", &"old".into(), Duration::from_secs(600));
        store.put("k", &"new".into(), Duration::from_secs(600));

        let store = restart(store, &path);
        assert_eq!(store.get("k").unwrap().0, "new");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_missing_key_is_absent_not_an_error() {
        let path = temp_path();
        let store = Store::<String>::open(&path).unwrap();
        assert!(store.get("never-written").is_none());
    }

    #[test]
    fn a_write_queued_at_shutdown_is_not_lost() {
        // The batching writer is why this needs a test: a put returns before
        // the transaction commits, so a stop that does not drain the queue
        // silently drops whatever was in it.
        let path = temp_path();
        let store = Store::<String>::open(&path).unwrap();
        for i in 0..1000 {
            store.put(&format!("k{i}"), &format!("v{i}"), Duration::from_secs(600));
        }

        let store = restart(store, &path);
        assert_eq!(store.len(), 1000);
        assert_eq!(store.get("k999").unwrap().0, "v999");
    }
}
