# enrichment-cache

A caching, normalising front end for the package metadata sources
[sbomify-action](https://github.com/sbomify/sbomify-action) reads.

Currently serves [ClearlyDefined](https://clearlydefined.io) only.

## Why

Three problems, none of which the client can solve for itself.

**The upstream is unreliable.** Sampled from one host, roughly 40% of cold
requests to `api.clearlydefined.io` returned nothing within 10 seconds — and
every one of those succeeded on retry within a second. A client that gives up
after one attempt records "this package has no metadata", which is indistinguishable
in the output from a package that genuinely has none. The result is an SBOM
that is quietly less complete, with nothing failing to say so.

**The same work is repeated everywhere.** Every user scanning a project that
depends on `lodash@4.17.21` asks the same question. One fetch can answer all of
them.

**The answers are enormous.** A definition carries a per-file analysis:
`lodash@4.17.21` is 189KB. Consumers read four fields totalling about 440 bytes
— a licence expression, the curated copyright holders, a homepage and a
repository URL. Caching 189KB to serve 0.2% of it wastes bandwidth at the edge
and parse time in every client.

| | per coordinate |
| --- | ---: |
| upstream definition | 18–190 KB |
| this service | **~0.4 KB** |

## API

```
GET /v1/clearlydefined/{type}/{provider}/{namespace}/{name}/{revision}
```

Use `-` for an absent namespace, matching ClearlyDefined's own coordinates.

```console
$ curl https://…/v1/clearlydefined/pypi/pypi/-/requests/2.32.3
{
  "declared": "Apache-2.0",
  "parties": ["Copyright Kenneth Reitz"],
  "homepage": null,
  "source_url": null,
  "harvested": true,
  "score": 73
}
```

`harvested` is the field worth understanding. **ClearlyDefined never 404s** — a
coordinate nobody has looked at yet returns `200` with an empty definition and a
score around 35, which is indistinguishable from "this package genuinely has no
licence" unless you check whether any tools ran. `harvested: false` means *not
examined yet*, and it will change. Treat it accordingly rather than recording it
as an absence.

Also available: `GET /healthz`, `GET /stats`.

## Behaviour

**Retries transient failures.** Timeouts, 429s and 5xx are retried with a short
linear backoff. Nothing transient is ever cached: persisting a stall as "no
data" is the failure this service exists to prevent.

**Collapses concurrent misses.** Thirty simultaneous requests for one cold
coordinate produce one upstream fetch. The fetch runs detached from the request
that triggered it, so a client that gives up does not abandon the work — without
that, collapsing evaporates exactly when the upstream is slow enough to matter.
Measured before that fix: 30 concurrent requests, 10 upstream fetches.

**Splits the TTL by harvest state.** A harvested definition is held for 30 days;
the coordinate is immutable and only a curation changes it. An unharvested one
is held for 6 hours, so a package harvested tomorrow is not remembered as empty
for a month. The `Cache-Control` sent to any CDN in front follows the same split.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `LISTEN_ADDR` | `0.0.0.0:8080` | Listen address |
| `CLEARLYDEFINED_UPSTREAM` | `https://api.clearlydefined.io` | Upstream base URL |
| `CACHE_CAPACITY` | `200000` | Maximum entries held in process |
| `UPSTREAM_ATTEMPTS` | `3` | Total attempts per fetch |
| `UPSTREAM_TIMEOUT_SECS` | `15` | Per-attempt timeout |

## Running

```console
$ docker build -t enrichment-cache .
$ docker run -p 8080:8080 enrichment-cache
```

The image is a static musl binary on `scratch` — about 5.5MB, no shell, no
package manager, running as uid 65532. TLS roots are compiled in, so there is
no system certificate store to mount.

It is designed to sit behind a CDN. The edge does the geographic work; this
process does the normalising and the collapsing.

## Why only ClearlyDefined

Because re-serving someone else's data is a licensing question, and
ClearlyDefined is the one source where the answer is unambiguous: its curated
data is [CC0-1.0](https://github.com/clearlydefined/curated-data/blob/master/LICENSE),
a public domain dedication that explicitly covers database rights and permits
redistribution for any purpose.

That does not generalise. `ecosyste.ms` publishes its data under CC BY-SA 4.0,
which carries attribution and share-alike obligations and sits alongside a
commercial licensing offer. Repology asks bulk consumers to use its database
dumps rather than the API. `deps.dev` publishes no data licence at all. None of
those should be added here without deciding, deliberately, that the terms allow
it.

## Licence

AGPL-3.0-or-later. See [LICENSE](LICENSE).
