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

Each commit on `main` that passes CI is published as a `linux/amd64`
image tagged with its full commit SHA:

```
ghcr.io/muutto365/avora-analytics:sha-<commit>
```

There is no `latest` tag. The image's source link points at that commit.

## Registration and creating accounts

Unlike upstream, an instance without any users only opens `/register`
when registration is enabled (`DISABLE_REGISTRATION=false`). With
`DISABLE_REGISTRATION=true` or `invite_only` (the default in the image),
registration stays closed from the first start, and accounts are
created server-side with the `create-user` task:

| Variable | Value |
|---|---|
| `CREATE_USER_EMAIL` | Email address of the account. |
| `CREATE_USER_NAME` | Display name. |
| `CREATE_USER_PASSWORD_FILE` | Path to a file containing only the password (a trailing newline is ignored). |

The image runs as uid 999, so the password file must be readable by
that uid without being readable by others. Either give it to uid 999
with mode `0400` on the host (as below, run as root), or mount it with
a secrets mechanism that sets the owner, for example a Kubernetes
secret volume with `defaultMode: 0440` and the pod's `fsGroup`. Do not
make it world-readable.

```sh
install -m 0400 -o 999 /dev/stdin ./password   # paste, then Ctrl-D
docker run --rm --read-only \
  --env-file app.env \
  -e CREATE_USER_EMAIL=admin@example.com \
  -e CREATE_USER_NAME=Admin \
  -e CREATE_USER_PASSWORD_FILE=/run/secrets/password \
  -v "$PWD/password:/run/secrets/password:ro" \
  ghcr.io/muutto365/avora-analytics:sha-<commit> db create-user
shred -u ./password
```

Inside a running container the same task is
`/app/create-user.sh` (or `/app/bin/plausible eval
Plausible.Release.create_user`). The password is only read from the
file, never from arguments or environment values, and is never printed.
It must pass the same rules as registration. The account's email is
marked verified, and two-factor authentication is set up from the
account settings after the first login, as for any other account. If an
account with that email already exists, the task leaves it unchanged
and exits successfully; invalid input exits non-zero. Surrounding
whitespace in the email and name is ignored.

## Single sign-on (OIDC)

Users can log in through any OpenID Connect provider instead of with a
password. The feature is off unless `OIDC_ISSUER` is set; without it the
login works as upstream. Like other settings, each variable can also be
given as a file named after it in `CONFIG_DIR` (default `/run/secrets`).

| Variable | Value |
|---|---|
| `OIDC_ISSUER` | Issuer URL, exactly as the provider's discovery document states it. Must be `https` (plain `http` only for `localhost`). |
| `OIDC_CLIENT_ID` | Client id registered at the provider. |
| `OIDC_CLIENT_SECRET_FILE` | Path to a file containing only the client secret. The secret is never read from an environment variable. |
| `OIDC_ALLOWED_GROUPS` | Optional comma-separated list. When set, only users whose groups claim contains at least one of these values may log in. Values are compared verbatim, so full group paths such as `/staff/analytics` work. |
| `OIDC_GROUPS_CLAIM` | Name of the ID token claim holding the groups (default `groups`). |
| `OIDC_BUTTON_LABEL` | Text of the login button (default `Sign in with SSO`). |
| `OIDC_DISABLE_PASSWORD_LOGIN` | `true` to allow single sign-on only (default `false`). |
| `OIDC_INTERNAL_ISSUER_URL` | Optional. Base URL at which the server reaches the provider when that differs from `OIDC_ISSUER` (for example a private network address). Only server-to-provider requests whose URL starts with `OIDC_ISSUER` are sent there; the browser and the expected `iss` claim keep using `OIDC_ISSUER`. |

Register a confidential client at the provider with:

- the authorization code flow and PKCE with `S256`;
- the redirect URI `<BASE_URL>/auth/oidc/callback`;
- the scopes `openid`, `email` and `profile`;
- `email`, `email_verified` and, when `OIDC_ALLOWED_GROUPS` is used, the
  groups claim included in the ID token. Claims that only the userinfo
  endpoint returns are not read.

On login the ID token's signature, issuer, audience, expiry and nonce
are checked, and the `state` value must match the one stored in the
browser session for that login, which expires after 10 minutes and is
used only once. The provider must report `email_verified` as `true`.
The account with the same email address (case-insensitive) is then
logged in; if there is none, an account is created with a verified
email and no password. `DISABLE_REGISTRATION` does not apply to these
accounts: who may log in is decided by the provider and
`OIDC_ALLOWED_GROUPS`. Sessions started through single sign-on are not
asked for this application's two-factor code, and a team's "require
2FA" setting does not apply to them; use the provider's multi-factor
authentication instead. Logging out ends the session here only, not
at the provider.

With `OIDC_DISABLE_PASSWORD_LOGIN=true` the login page shows only the
single sign-on button, and the password login, password reset and the
two-factor step that follows a password are refused. Set
`DISABLE_REGISTRATION=true` as well: registration finishes with a
password login, so it cannot complete. There is no other way in while
the setting is on; to recover from a provider outage, unset it and
restart.

Accounts are matched by email address, so anyone who controls an
address at the provider gets the existing account with that address.
Only connect a provider whose email addresses you trust, and keep
registration closed so nobody can create a password account ahead of
the person who owns that address.

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
