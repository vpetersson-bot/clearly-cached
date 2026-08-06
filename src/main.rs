//! A caching, normalising front end for package metadata sources.
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
//! It is deliberately not a general proxy. Only ClearlyDefined is served,
//! because its curated data is CC0-1.0; the other sources sbomify-action reads
//! carry terms that do not obviously permit re-serving them.
//!
//! Designed to sit behind a CDN. The Cache-Control it emits is the useful knob:
//! the edge does the geographic work, this process does the normalising and the
//! collapsing.

mod cache;
mod clearlydefined;

use std::collections::HashMap;
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

/// Harvested definitions change only when someone curates them, and the
/// coordinate itself is immutable. Long, but not forever.
const TTL_HARVESTED: Duration = Duration::from_secs(30 * 24 * 3600);
/// An unharvested coordinate is "not looked at yet", not "no licence". It will
/// change, so it must expire soon enough to pick that up.
const TTL_UNHARVESTED: Duration = Duration::from_secs(6 * 3600);

#[derive(Default)]
struct Stats {
    hits: AtomicU64,
    misses: AtomicU64,
    upstream_errors: AtomicU64,
}

/// Result shared between everyone waiting on one in-flight fetch.
type Shared = Result<Definition, String>;

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
            "sbomify-enrichment-cache/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/sbomify/enrichment-cache)"
        ))
        .build()
        .expect("failed to build HTTP client");

    let state = Arc::new(AppState {
        cache: Cache::new(capacity),
        client: Client::new(http, upstream.clone(), attempts),
        stats: Stats::default(),
        inflight: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route(
            "/v1/clearlydefined/{kind}/{provider}/{namespace}/{name}/{revision}",
            get(definition),
        )
        .route("/healthz", get(|| async { "ok" }))
        .route("/stats", get(stats))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {addr}: {e}"));
    eprintln!("enrichment-cache listening on {addr}, upstream {upstream}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server error");
}

async fn stats(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "entries": state.cache.len(),
        "hits": state.stats.hits.load(Ordering::Relaxed),
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
        return serve(def, true);
    }

    // Collapse concurrent misses onto one upstream fetch.
    let mut receiver = {
        let mut inflight = state.inflight.lock().await;

        // Re-check under the map lock: the fetch may have finished between the
        // cache miss above and getting here.
        if let Some(def) = state.cache.get(&key) {
            state.stats.hits.fetch_add(1, Ordering::Relaxed);
            return serve(def, true);
        }

        match inflight.get(&key) {
            Some(tx) => tx.subscribe(),
            None => {
                let (tx, rx) = broadcast::channel(1);
                inflight.insert(key.clone(), tx);
                state.stats.misses.fetch_add(1, Ordering::Relaxed);
                spawn_fetch(state.clone(), coord.clone(), key.clone());
                rx
            }
        }
    };

    match receiver.recv().await {
        Ok(shared) => match &*shared {
            Ok(def) => serve(def.clone(), false),
            Err(message) => error(StatusCode::GATEWAY_TIMEOUT, message),
        },
        // The sender was dropped without publishing, which means the fetch task
        // itself died. Report it rather than hanging.
        Err(_) => error(StatusCode::BAD_GATEWAY, "fetch task ended unexpectedly"),
    }
}

/// Run one upstream fetch, publish the outcome, and cache a success.
///
/// Detached from any request on purpose -- see `AppState::inflight`.
fn spawn_fetch(state: Arc<AppState>, coord: Coordinate, key: String) {
    tokio::spawn(async move {
        let outcome: Shared = match state.client.fetch(&coord).await {
            Ok(def) => {
                let ttl = if def.harvested {
                    TTL_HARVESTED
                } else {
                    TTL_UNHARVESTED
                };
                state.cache.insert(key.clone(), def.clone(), ttl);
                Ok(def)
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

        // Remove before publishing, so a request arriving after the result is
        // sent starts a fresh fetch rather than subscribing to a channel that
        // will never send again.
        let sender = state.inflight.lock().await.remove(&key);
        if let Some(tx) = sender {
            let _ = tx.send(Arc::new(outcome));
        }
    });
}

fn serve(def: Definition, hit: bool) -> Response {
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
                if hit { "HIT".into() } else { "MISS".into() },
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
