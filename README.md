# Avora Analytics

Avora Analytics is a modified version of
[Plausible Analytics](https://github.com/plausible/analytics) Community
Edition. It is not affiliated with or endorsed by Plausible Insights OÜ.

The upstream version this tree is based on is recorded in
[`UPSTREAM`](UPSTREAM).

## Licence

- This repository is licensed under the GNU Affero General Public
  License v3.0, see [`LICENSE.md`](LICENSE.md).
- The tracker script in [`tracker/`](tracker) is licensed under the MIT
  licence, see [`tracker/LICENSE.md`](tracker/LICENSE.md).

## Building

The Docker image builds the Community Edition release:

```sh
docker build --build-arg MIX_ENV=ce -t avora-analytics .
```

Tests run with `MIX_ENV=ce_test` against PostgreSQL and ClickHouse; see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the exact
steps and service versions.

## Security updates and upstream releases

- [`.github/workflows/security.yml`](.github/workflows/security.yml)
  audits the Hex and npm dependencies and the Docker image. Its header
  states which findings fail a pull request. A daily run keeps one issue
  labelled `security` with the unresolved findings.
- [`.github/workflows/upstream.yml`](.github/workflows/upstream.yml)
  keeps one issue labelled `upstream` with new upstream releases and
  upstream advisories that affect the version in `UPSTREAM`.
- [`docs/upstream-upgrades.md`](docs/upstream-upgrades.md) describes how
  an upstream release is applied.

## Client IP addresses

The client IP is used for visitor counting, geolocation and login rate
limits. Forwarded-IP headers are only read from senders that overwrite
them; nothing else is ever trusted (in particular `X-Forwarded-For` and
`Forwarded` are ignored unless named below).

| Setting | Effect | What the sender must do |
|---|---|---|
| `INGEST_KEY` | Requests whose `x-ingest-key` header matches use `X-Plausible-IP`. | Send the key and **overwrite** `X-Plausible-IP` with the client IP. Never pass a client-supplied `x-ingest-key` through. |
| `TRUSTED_PROXY_CIDRS` + `TRUSTED_PROXY_IP_HEADER` | Requests whose connection peer is in one of the ranges (comma-separated) use the named header. | The proxy at those addresses must **overwrite** that header with the client IP on every request. |
| neither | The connection's peer IP is used. | — |

The header must contain a single IP address (a port is allowed); any
other value falls back to the peer IP.
