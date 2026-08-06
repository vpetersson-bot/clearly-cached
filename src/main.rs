//! A caching, normalising front end for the ClearlyDefined definitions API.
//!
//! Sits between sbomify-action and api.clearlydefined.io and does three things
//! the client cannot do for itself:
//!
//!   * **absorbs an unreliable upstream** — retries a stall rather than
//!     recording it as "this package has no metadata", which is how a
//!     rate-limited or timed-out lookup silently produced a thinner SBOM;
//!   * **collapses duplicate work** — every user asking about the same package
//!     version shares one upstream fetch, rather than each paying for it;
//!   * **shrinks the answer** — a definition is up to ~190KB of per-file
//!     analysis and consumers read four fields of it.
//!
//! One upstream, on purpose. ClearlyDefined's curated data is CC0-1.0, which is
//! what makes caching and re-serving it unambiguous; the other sources
//! sbomify-action reads carry terms that do not obviously permit the same, and
//! a service that reflected arbitrary paths upstream would be a general proxy
//! for whoever found it. Neither is a gap to be filled later.
//!
//! Designed to sit behind a CDN. The Cache-Control it emits is the useful knob:
//! the edge does the geographic work, this process does the normalising and the
//! collapsing.

mod cache;
mod clearlydefined;
mod persist;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use tokio::sync::{broadcast, Mutex};

use cache::Cache;
use clearlydefined::{Client, Coordinate, Definition, FetchError};
use persist::Store;

/// Harvested definitions change only when someone curates them, and the
/// coordinate itself is immutable. Long, but not forever.
const TTL_HARVESTED: Duration = Duration::from_secs(30 * 24 * 3600);
/// An unharvested coordinate is "not looked at yet", not "no licence". It will
/// change, so it must expire soon enough to pick that up.
const TTL_UNHARVESTED: Duration = Duration::from_secs(6 * 3600);

/// How often expired entries are deleted from disk. Nothing else removes them,
/// and nothing depends on it being prompt -- an expired entry is already
/// invisible to reads, it just occupies a page until swept.
const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// Default on-disk location. A container gets persistence by mounting a volume
/// here and nothing worse than a warning by not doing so.
const DEFAULT_CACHE_PATH: &str = "/var/cache/clearly-cached/definitions.redb";

#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    /// Served from disk after the memory map had evicted or never held it. The
    /// number that says whether the disk tier is earning its keep.
    disk_hits: AtomicU64,
    misses: AtomicU64,
    upstream_errors: AtomicU64,
}

/// Where an answer came from. Reported as `x-cache` so a CDN or an operator can
/// tell an evicted-but-cached coordinate from one that cost an upstream fetch.
#[derive(Debug, Clone, Copy)]
enum Source {
    Memory,
    Disk,
    Upstream,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "HIT",
            Self::Disk => "HIT-DISK",
            Self::Upstream => "MISS",
        }
    }
}

/// Result shared between everyone waiting on one in-flight resolve.
type Shared = Result<(Definition, Source), String>;

struct AppState {
    cache: Cache<Definition>,
    client: Client,
    stats: Stats,
    /// Coordinates currently being fetched, and how to hear the answer.
    ///
    /// The fetch runs in a spawned task rather than inline in the request that
    /// triggered it. That detail is the difference between collapsing working
    /// and collapsing evaporating under load: a client that gives up mid-fetch
    /// cancels its handler, and with an inline fetch that would abandon the
    /// upstream call and let the next waiter start another. Measured before
    /// this change, 30 concurrent requests for one cold coordinate produced 10
    /// upstream fetches instead of 1, precisely because the upstream was slow
    /// enough for callers to time out. Spawning means the work completes and
    /// populates the cache even if every caller has walked away.
    inflight: Mutex<HashMap<String, broadcast::Sender<Arc<Shared>>>>,
    /// The disk tier: everything ever fetched and not yet expired.
    ///
    /// The map above evicts under pressure, this does not. A definition pushed
    /// out of memory is still here, and reading it back costs a disk seek
    /// rather than a round trip to an upstream that stalls on 40% of cold
    /// requests. `None` when the path could not be opened -- persistence is an
    /// optimisation, and refusing to start without it would turn a missing
    /// volume into an outage.
    store: Option<Store<Definition>>,
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let upstream = std::env::var("CLEARLYDEFINED_UPSTREAM")
        .unwrap_or_else(|_| clearlydefined::UPSTREAM.into());
    let capacity = env_u64("CACHE_CAPACITY", 200_000) as usize;
    let attempts = env_u64("UPSTREAM_ATTEMPTS", 3) as u32;
    let timeout = Duration::from_secs(env_u64("UPSTREAM_TIMEOUT_SECS", 15));

    let http = reqwest::Client::builder()
        .timeout(timeout)
        // Upstream stalls rather than refusing, so a connect timeout well below
        // the request timeout distinguishes "unreachable" from "thinking".
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!(
            "clearly-cached/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/sbomify/clearly-cached)"
        ))
        .build()
        .expect("failed to build HTTP client");

    // Nothing is preloaded: the disk tier exists so that memory does not have
    // to hold everything, and reading it all back at boot would undo that. The
    // map warms from traffic, and until it does a miss costs a disk read
    // instead of an upstream fetch.
    let store = match cache_path() {
        None => None,
        Some(path) => match Store::open(&path) {
            Ok(store) => {
                eprintln!(
                    "cache: {} entries on disk at {}",
                    store.len(),
                    path.display()
                );
                Some(store)
            }
            Err(e) => {
                // Almost always a missing or unwritable volume. Worth saying
                // loudly, not worth refusing to serve over.
                eprintln!(
                    "cache: running memory-only, cannot use {}: {e}",
                    path.display()
                );
                None
            }
        },
    };

    let state = Arc::new(AppState {
        cache: Cache::new(capacity),
        client: Client::new(http, upstream.clone(), attempts),
        stats: Stats::default(),
        inflight: Mutex::new(HashMap::new()),
        store,
    });

    let app = Router::new()
        // Mirrors upstream's own path shape, minus the leading /definitions
        // being qualified by anything: there is only one upstream, so a
        // /clearlydefined/ segment would say nothing the service name does not.
        .route(
            "/v1/definitions/{kind}/{provider}/{namespace}/{name}/{revision}",
            get(definition),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/stats", get(stats))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
    eprintln!("clearly-cached listening on {addr}, upstream {upstream}");

    if state.store.is_some() {
        let state = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_EVERY);
            tick.tick().await; // interval fires immediately; skip that one.
            loop {
                tick.tick().await;
                if let Some(store) = &state.store {
                    store.sweep();
                }
            }
        });
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");

    // Let queued writes land before the process goes away. Losing them costs
    // only a re-fetch, but there is no reason to lose them on a clean stop.
    if let Some(store) = &state.store {
        store.shutdown();
    }
}

/// Where the cache is persisted. `CACHE_PATH=` (empty) means memory only.
fn cache_path() -> Option<PathBuf> {
    match std::env::var("CACHE_PATH") {
        Ok(p) if p.is_empty() => None,
        Ok(p) => Some(PathBuf::from(p)),
        Err(_) => Some(PathBuf::from(DEFAULT_CACHE_PATH)),
    }
}

/// SIGTERM as well as SIGINT: `docker stop` and every orchestrator send the
/// former, and that is the shutdown that has a cache worth writing out.
async fn shutdown_signal() {
    let interrupt = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
    eprintln!("clearly-cached shutting down");
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "entries": state.cache.len(),
        "disk_entries": state.store.as_ref().map(|s| s.len()),
        "hits": state.stats.hits.load(Ordering::Relaxed),
        "disk_hits": state.stats.disk_hits.load(Ordering::Relaxed),
        "misses": state.stats.misses.load(Ordering::Relaxed),
        "upstream_errors": state.stats.upstream_errors.load(Ordering::Relaxed),
    }))
}

async fn definition(
    State(state): State<Arc<AppState>>,
    Path((kind, provider, namespace, name, revision)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
) -> Response {
    let coord = match Coordinate::parse(&kind, &provider, &namespace, &name, &revision) {
        Ok(c) => c,
        Err(e) => return error(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    let key = coord.cache_key();

    if let Some(def) = state.cache.get(&key) {
        state.stats.hits.fetch_add(1, Ordering::Relaxed);
        return serve(def, Source::Memory);
    }

    // Collapse everything past this point -- the disk read as well as the fetch.
    // Thirty simultaneous requests for one evicted coordinate should be one
    // disk read, for the same reason they should be one upstream fetch.
    let mut receiver = {
        let mut inflight = state.inflight.lock().await;

        // Re-check under the map lock: the resolve may have finished between
        // the cache miss above and getting here.
        if let Some(def) = state.cache.get(&key) {
            state.stats.hits.fetch_add(1, Ordering::Relaxed);
            return serve(def, Source::Memory);
        }

        match inflight.get(&key) {
            Some(tx) => tx.subscribe(),
            None => {
                let (tx, rx) = broadcast::channel(1);
                inflight.insert(key.clone(), tx);
                spawn_resolve(state.clone(), coord.clone(), key.clone());
                rx
            }
        }
    };

    match receiver.recv().await {
        Ok(shared) => match &*shared {
            Ok((def, source)) => serve(def.clone(), *source),
            Err(message) => error(StatusCode::GATEWAY_TIMEOUT, message),
        },
        // The sender was dropped without publishing, which means the resolve
        // task itself died. Report it rather than hanging.
        Err(_) => error(StatusCode::BAD_GATEWAY, "fetch task ended unexpectedly"),
    }
}

/// Resolve one coordinate: disk first, upstream if it is not there.
///
/// Detached from any request on purpose -- see `AppState::inflight`.
fn spawn_resolve(state: Arc<AppState>, coord: Coordinate, key: String) {
    tokio::spawn(async move {
        if let Some((def, ttl)) = read_from_disk(&state, &key).await {
            state.stats.disk_hits.fetch_add(1, Ordering::Relaxed);
            // Promote, with the TTL it has left rather than a fresh one: the
            // disk copy expires when it was always going to.
            state.cache.insert(key.clone(), def.clone(), ttl);
            publish(&state, &key, Ok((def, Source::Disk))).await;
            return;
        }

        state.stats.misses.fetch_add(1, Ordering::Relaxed);
        let outcome: Shared = match state.client.fetch(&coord).await {
            Ok(def) => {
                let ttl = if def.harvested {
                    TTL_HARVESTED
                } else {
                    TTL_UNHARVESTED
                };
                state.cache.insert(key.clone(), def.clone(), ttl);
                if let Some(store) = &state.store {
                    store.put(&key, &def, ttl);
                }
                Ok((def, Source::Upstream))
            }
            Err(FetchError::Upstream(code)) => {
                // Upstream answered definitively. Not cached: it tells us
                // nothing about the coordinate a later request would not
                // re-learn.
                state.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                Err(format!("upstream returned {code}"))
            }
            Err(e) => {
                // Transient, and already retried. Never cached -- persisting a
                // stall as "no data" is the failure this service exists to
                // prevent.
                state.stats.upstream_errors.fetch_add(1, Ordering::Relaxed);
                Err(e.to_string())
            }
        };

        publish(&state, &key, outcome).await;
    });
}

/// Hand the result to everyone waiting and stop collecting new waiters.
///
/// Removed from the map before publishing, so a request arriving after the
/// result is sent starts a fresh resolve rather than subscribing to a channel
/// that will never send again.
async fn publish(state: &AppState, key: &str, outcome: Shared) {
    let sender = state.inflight.lock().await.remove(key);
    if let Some(tx) = sender {
        let _ = tx.send(Arc::new(outcome));
    }
}

/// Look the coordinate up in the disk tier.
///
/// On a blocking thread: a warm read is a page-cache hit, but a cold one is a
/// disk seek, and the runtime's worker threads are also serving requests.
async fn read_from_disk(state: &Arc<AppState>, key: &str) -> Option<(Definition, Duration)> {
    state.store.as_ref()?;
    let state = state.clone();
    let key = key.to_owned();
    tokio::task::spawn_blocking(move || state.store.as_ref()?.get(&key))
        .await
        .ok()
        .flatten()
}

fn serve(def: Definition, source: Source) -> Response {
    // The edge TTL follows the same split as the local one: an unharvested
    // answer must not be pinned at a CDN for a month either.
    let max_age = if def.harvested {
        TTL_HARVESTED.as_secs()
    } else {
        TTL_UNHARVESTED.as_secs()
    };
    (
        StatusCode::OK,
        [
            (
                header::CACHE_CONTROL,
                format!("public, max-age={max_age}, stale-if-error=86400"),
            ),
            (
                header::HeaderName::from_static("x-cache"),
                source.as_str().to_owned(),
            ),
        ],
        Json(def),
    )
        .into_response()
}

fn error(code: StatusCode, message: &str) -> Response {
    (
        code,
        // Never cache an error: a stall cached at the edge would be the same
        // silent data loss, one layer further out.
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}
