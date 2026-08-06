//! Fetching and normalising ClearlyDefined definitions.
//!
//! Two things this module exists to do.
//!
//! **Shrink the payload.** A definition carries a per-file analysis: lodash
//! 4.17.21 is 189KB. Consumers use four fields out of it, totalling about 440
//! bytes. Caching the full document to serve 0.2% of it wastes bandwidth at the
//! edge and parse time on every client, so the projection happens here, once,
//! rather than in every client on every lookup.
//!
//! **Survive a flaky upstream.** Sampled from one host, roughly 40% of cold
//! requests to api.clearlydefined.io returned nothing within 10 seconds, and
//! every one of those succeeded on retry within a second. A single attempt is
//! the difference between a populated SBOM and a silently empty one, so this
//! retries rather than passing the stall on.
//!
//! ClearlyDefined's curated data is CC0-1.0, which is why this service caches
//! and re-serves it. That is a property of this source specifically and does not
//! generalise to the other sources sbomify-action reads.

use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const UPSTREAM: &str = "https://api.clearlydefined.io";

/// Coordinate type/provider pairs this service will forward.
///
/// An allow-list, not a convenience: without it any path under /v1/ would be
/// reflected into an upstream URL, which makes the service a general-purpose
/// proxy for whoever finds it.
const ALLOWED_TYPES: &[(&str, &str)] = &[
    ("pypi", "pypi"),
    ("npm", "npmjs"),
    ("crate", "cratesio"),
    ("maven", "mavencentral"),
    ("gem", "rubygems"),
    ("nuget", "nuget"),
    ("go", "golang"),
    ("deb", "debian"),
    ("composer", "packagist"),
    ("pod", "cocoapods"),
];

/// The projection clients actually consume.
///
/// `Deserialize` for the on-disk cache only: nothing upstream is parsed into
/// this type, it is built field by field in `normalise`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Definition {
    /// SPDX expression as declared, or None when nothing was found.
    pub declared: Option<String>,
    /// Curated copyright holders. ClearlyDefined's distinctive contribution:
    /// no other source sbomify-action reads supplies attribution.
    pub parties: Vec<String>,
    pub homepage: Option<String>,
    /// Only when it looks like a repository. Upstream returns a sources-jar
    /// download for Maven and a project page for PyPI, neither of which is a
    /// repository however much the field name suggests otherwise.
    pub source_url: Option<String>,
    /// Whether any tool has actually looked at this coordinate.
    ///
    /// The caller keys the TTL off this. An unharvested definition is not
    /// "no licence", it is "not yet examined", and it will change.
    pub harvested: bool,
    pub score: u64,
}

#[derive(Debug)]
pub enum FetchError {
    /// Worth retrying, and worth not caching: a stall, a 429, a 5xx.
    Transient(String),
    /// Upstream answered definitively.
    Upstream(u16),
    /// The coordinate is not one we forward.
    Rejected(&'static str),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(m) => write!(f, "transient upstream failure: {m}"),
            Self::Upstream(c) => write!(f, "upstream returned {c}"),
            Self::Rejected(m) => write!(f, "{m}"),
        }
    }
}

/// A validated ClearlyDefined coordinate.
#[derive(Debug, Clone, PartialEq)]
pub struct Coordinate {
    pub kind: String,
    pub provider: String,
    pub namespace: String,
    pub name: String,
    pub revision: String,
}

impl Coordinate {
    pub fn parse(
        kind: &str,
        provider: &str,
        namespace: &str,
        name: &str,
        revision: &str,
    ) -> Result<Self, FetchError> {
        if !ALLOWED_TYPES
            .iter()
            .any(|(t, p)| *t == kind && *p == provider)
        {
            return Err(FetchError::Rejected("unsupported type/provider"));
        }
        for segment in [namespace, name, revision] {
            if !is_safe_segment(segment) {
                return Err(FetchError::Rejected("invalid coordinate segment"));
            }
        }
        Ok(Self {
            kind: kind.to_owned(),
            provider: provider.to_owned(),
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            revision: revision.to_owned(),
        })
    }

    pub fn cache_key(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}",
            self.kind, self.provider, self.namespace, self.name, self.revision
        )
    }
}

/// Segments that can be placed in an upstream path without changing its shape.
///
/// Rejects traversal and separators outright rather than escaping them: every
/// legitimate coordinate is already within this set, so anything outside it is
/// a probe rather than a package.
///
/// `%` is excluded, and that exclusion is the whole guard rather than a
/// tidiness rule. Axum decodes a captured segment once, so `%252e%252e%252f`
/// reaches here as `%2e%2e%2f`; allowing `%` would let that through, and the
/// URL crate does not normalise percent-encoded dot-segments, so it would
/// arrive at upstream intact and be decoded there during routing. The result is
/// a request for a different endpoint, projected and cached under the
/// coordinate the caller named -- which is this service acting as the general
/// proxy the allow-list exists to prevent.
fn is_safe_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+' | '@' | '~'))
}

/// Hosts whose URLs are repositories. Everything else upstream puts in
/// `sourceLocation.url` is a download or a registry page.
const VCS_HOSTS: &[&str] = &[
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "sr.ht",
];

/// Schemes a repository URL can plausibly carry.
///
/// Checked because `sourceLocation.url` comes from community-submitted
/// curations and this field is served to consumers that render it as a link.
/// `javascript://github.com/%0aalert(1)` has a VCS host and no archive
/// extension, so without a scheme check it would be published as a repository.
const VCS_SCHEMES: &[&str] = &["https", "http", "git", "git+https", "git+ssh", "ssh"];

fn is_vcs_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let scheme = scheme.to_ascii_lowercase();
    if !VCS_SCHEMES.contains(&scheme.as_str()) {
        return false;
    }
    let host = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let path = rest.split_once('/').map(|(_, p)| p).unwrap_or("");
    let path = path.split(['?', '#']).next().unwrap_or("");
    if [
        ".jar", ".zip", ".gz", ".tgz", ".whl", ".gem", ".crate", ".bz2", ".xz",
    ]
    .iter()
    .any(|ext| path.to_ascii_lowercase().ends_with(ext))
    {
        return false;
    }
    VCS_HOSTS
        .iter()
        .any(|h| host == *h || host.ends_with(&format!(".{h}")))
}

/// Pick the most useful attribution party.
///
/// Scanners emit every copyright line they find, so the list is usually several
/// spellings of one holder. The undated form is the canonical one; falling back
/// to the first keeps the choice stable when every line carries a year.
fn cleanest_party(parties: &[String]) -> Vec<String> {
    let cleaned: Vec<String> = parties
        .iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    if cleaned.is_empty() {
        return Vec::new();
    }
    let undated: Vec<String> = cleaned
        .iter()
        .filter(|p| !contains_year(p))
        .cloned()
        .collect();
    let preferred = undated.first().or_else(|| cleaned.first());
    let mut out = Vec::with_capacity(cleaned.len());
    if let Some(first) = preferred {
        out.push(first.clone());
        for p in &cleaned {
            if p != first {
                out.push(p.clone());
            }
        }
    }
    out
}

fn contains_year(s: &str) -> bool {
    s.as_bytes().windows(4).any(|w| {
        (w[0] == b'1' && w[1] == b'9' || w[0] == b'2' && w[1] == b'0')
            && w[2].is_ascii_digit()
            && w[3].is_ascii_digit()
    })
}

/// Project an upstream definition down to the fields consumers read.
pub fn normalise(doc: &serde_json::Value) -> Definition {
    let licensed = doc.get("licensed");
    let described = doc.get("described");

    let declared = licensed
        .and_then(|l| l.get("declared"))
        .and_then(|d| d.as_str())
        .filter(|d| !d.is_empty() && *d != "NOASSERTION")
        .map(str::to_owned);

    // Attribution lives under facets.core, not at licensed.attribution --
    // upstream leaves the latter unset, and reading it yields nothing at all.
    let parties: Vec<String> = licensed
        .and_then(|l| l.pointer("/facets/core/attribution/parties"))
        .or_else(|| licensed.and_then(|l| l.pointer("/attribution/parties")))
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();

    let homepage = described
        .and_then(|d| d.get("projectWebsite"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    let source_url = described
        .and_then(|d| d.pointer("/sourceLocation/url"))
        .and_then(|v| v.as_str())
        .filter(|u| is_vcs_url(u))
        .map(str::to_owned);

    // Tools are the evidence that something looked. An unharvested coordinate
    // still returns 200 with a score around 35 and no tools.
    let harvested = described
        .and_then(|d| d.get("tools"))
        .and_then(|t| t.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    let score = doc
        .pointer("/scores/effective")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Definition {
        declared,
        parties: cleanest_party(&parties),
        homepage,
        source_url,
        harvested,
        score,
    }
}

pub struct Client {
    http: reqwest::Client,
    upstream: String,
    attempts: u32,
}

impl Client {
    pub fn new(http: reqwest::Client, upstream: String, attempts: u32) -> Self {
        Self {
            http,
            upstream,
            attempts: attempts.max(1),
        }
    }

    pub async fn fetch(&self, coord: &Coordinate) -> Result<Definition, FetchError> {
        let url = format!("{}/definitions/{}", self.upstream, coord.cache_key());
        let mut last = FetchError::Transient("no attempt made".into());

        for attempt in 0..self.attempts {
            if attempt > 0 {
                // Short, linear backoff. The observed stalls cleared on the
                // next try within a second; a long backoff would cost more
                // than the failure it is pacing.
                tokio::time::sleep(Duration::from_millis(250 * attempt as u64)).await;
            }
            match self.try_once(&url).await {
                Ok(def) => return Ok(def),
                Err(FetchError::Transient(m)) => last = FetchError::Transient(m),
                Err(other) => return Err(other),
            }
        }
        Err(last)
    }

    async fn try_once(&self, url: &str) -> Result<Definition, FetchError> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| FetchError::Transient(e.to_string()))?;

        let status = response.status().as_u16();
        if status == 429 || (500..600).contains(&status) {
            return Err(FetchError::Transient(format!("HTTP {status}")));
        }
        if status != 200 {
            return Err(FetchError::Upstream(status));
        }

        let doc: serde_json::Value = response
            .json()
            .await
            .map_err(|e| FetchError::Transient(format!("malformed body: {e}")))?;
        Ok(normalise(&doc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_unknown_type_provider_pairs() {
        assert!(Coordinate::parse("pypi", "evil", "-", "x", "1").is_err());
        assert!(Coordinate::parse("pypi", "pypi", "-", "x", "1").is_ok());
    }

    #[test]
    fn rejects_traversal_and_separators() {
        // The allow-list is what stops this becoming an open proxy.
        for bad in ["..", ".", "a/b", "a?b", "a#b", "", "a b"] {
            assert!(
                Coordinate::parse("pypi", "pypi", "-", bad, "1").is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn rejects_percent_encoded_traversal() {
        // What arrives after axum has decoded the path once, which is what a
        // caller sending %252e%252e%252f produces. Left intact these reach
        // upstream still encoded and are decoded there, addressing a different
        // endpoint under the coordinate the caller named.
        for bad in ["%2e%2e%2fcurations", "%2F", "a%00b", "%2e%2e"] {
            assert!(
                Coordinate::parse("pypi", "pypi", "-", bad, "1").is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn reads_attribution_from_the_core_facet() {
        // The whole reason this projection exists: licensed.attribution is
        // unset upstream, and reading it returns nothing.
        let doc = json!({
            "licensed": {
                "declared": "Apache-2.0",
                "attribution": null,
                "facets": {"core": {"attribution": {"parties": ["Copyright Kenneth Reitz"]}}}
            },
            "described": {"tools": ["scancode/32.7.0"]},
            "scores": {"effective": 73}
        });
        let d = normalise(&doc);
        assert_eq!(d.declared.as_deref(), Some("Apache-2.0"));
        assert_eq!(d.parties, vec!["Copyright Kenneth Reitz".to_string()]);
        assert!(d.harvested);
    }

    #[test]
    fn prefers_the_undated_copyright_line() {
        let doc = json!({
            "licensed": {"facets": {"core": {"attribution": {"parties": [
                "copyright (c) 2012 by Kenneth Reitz",
                "Copyright Kenneth Reitz"
            ]}}}},
            "described": {"tools": ["scancode/32.7.0"]}
        });
        assert_eq!(normalise(&doc).parties[0], "Copyright Kenneth Reitz");
    }

    #[test]
    fn an_unharvested_definition_is_not_no_licence() {
        // 200 with no tools and a low score. Must be distinguishable, because
        // it decides how long the answer is cached.
        let doc = json!({"licensed": {}, "described": {}, "scores": {"effective": 35}});
        let d = normalise(&doc);
        assert!(!d.harvested);
        assert_eq!(d.declared, None);
        assert_eq!(d.score, 35);
    }

    #[test]
    fn noassertion_is_not_a_licence() {
        let doc = json!({"licensed": {"declared": "NOASSERTION"}, "described": {}});
        assert_eq!(normalise(&doc).declared, None);
    }

    #[test]
    fn source_url_only_when_it_is_a_repository() {
        let repo = json!({"described": {"sourceLocation": {"url": "https://github.com/lodash/lodash/tree/abc"}}});
        assert!(normalise(&repo).source_url.is_some());

        // A Maven sources jar and a PyPI project page are not repositories.
        for not_repo in [
            "https://search.maven.org/remotecontent?filepath=x/commons-lang3-3.12.0-sources.jar",
            "https://pypi.org/project/requests/2.32.3/",
            "https://notgithub.com/evil/repo",
            "https://example.com/?ref=github.com",
            // Curations are community-submitted and this field gets rendered
            // as a link, so the scheme has to be checked too.
            "javascript://github.com/%0aalert(document.domain)",
            "data://github.com/x",
            "javascript:alert(1)",
        ] {
            let doc = json!({"described": {"sourceLocation": {"url": not_repo}}});
            assert_eq!(normalise(&doc).source_url, None, "accepted {not_repo}");
        }
    }

    #[test]
    fn the_projection_is_far_smaller_than_the_source() {
        // The reason this service normalises rather than proxying verbatim.
        let mut files = Vec::new();
        for i in 0..500 {
            files.push(
                json!({"path": format!("lib/file{i}.js"), "hashes": {"sha1": "a".repeat(40)}}),
            );
        }
        let doc = json!({
            "licensed": {"declared": "MIT", "facets": {"core": {"attribution": {"parties": ["Copyright X"]}}}},
            "described": {"tools": ["scancode/32.7.0"]},
            "files": files
        });
        let full = serde_json::to_string(&doc).unwrap().len();
        let projected = serde_json::to_string(&normalise(&doc)).unwrap().len();
        assert!(
            projected * 20 < full,
            "projection {projected} vs source {full} — not worth doing"
        );
    }
}
