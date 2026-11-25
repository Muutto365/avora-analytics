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
| `OIDC_ROLE_MAP` | Required. Comma-separated `<client role>=<role>` pairs: which of the provider's client roles on this client may sign in, and the role each grants here (`viewer`, `editor` or `admin`), for example `analytics-admin=admin,analytics-viewer=viewer`. See "Roles". |
| `OIDC_BUTTON_LABEL` | Text of the login button (default `Sign in with SSO`). |
| `OIDC_SESSION_HOURS` | Lifetime of a session started through single sign-on, 1 to 72 hours (default 12). |
| `OIDC_DISABLE_PASSWORD_LOGIN` | `true` to allow single sign-on only (default `false`). |
| `OIDC_INTERNAL_ISSUER_URL` | Optional. Base URL at which the server reaches the provider when that differs from `OIDC_ISSUER` (for example a private network address). Only server-to-provider requests whose URL starts with `OIDC_ISSUER` are sent there; the browser and the expected `iss` claim keep using `OIDC_ISSUER`. Must be `https`, with a certificate valid for the internal host name, unless it is `localhost` or `OIDC_INTERNAL_ISSUER_ALLOW_HTTP` is set. |
| `OIDC_INTERNAL_ISSUER_ALLOW_HTTP` | `true` to allow a plain `http` `OIDC_INTERNAL_ISSUER_URL`. The client secret, the authorization code and the tokens then cross that path unencrypted, so use it only for a network path you trust, such as a private cluster network. |

Register a confidential client at the provider with:

- the authorization code flow and PKCE with `S256`;
- client authentication with the client secret (`client_secret_basic`
  or `client_secret_post`);
- the redirect URI `<BASE_URL>/auth/oidc/callback`;
- the scopes `openid`, `email` and `profile`;
- `email`, `email_verified` and the client's roles included in the ID
  token as `resource_access.<OIDC_CLIENT_ID>.roles` (the shape of a
  client-role mapper). Claims that only the userinfo endpoint or the
  access token carry are not read.

The settings are checked at startup, and an incomplete configuration or
an unreadable secret file stops the application. This also applies to
one-off commands such as `create-user`, so run them with the same
variables and the secret file mounted. If the provider cannot be
reached, the application still starts, password login (unless disabled)
keeps working, and the single sign-on button reports that it is
temporarily unavailable until the provider is back.

### How logins are checked

On login the ID token's signature, issuer, audience, expiry and nonce
are checked, and the `state` value must match the one stored in the
browser session for that login, which expires after 10 minutes and is
used only once. The provider must report `email_verified` as `true`,
and the ID token must grant a role through `OIDC_ROLE_MAP`.

Accounts are bound to the provider's identity (the issuer and the
subject identifier, `sub`):

- A user the provider has signed in before is found by that identity.
  If the provider now reports a different email address, the account's
  address follows it, unless another account already has that address,
  in which case the login is refused.
- The first time an identity signs in, it is linked to the existing
  account with the same email address (case-insensitive), but only if
  that account's address is verified, it has no pending email change and
  it is not linked to another identity. Otherwise the login is refused;
  an administrator has to resolve the conflicting account. Linking ends
  the account's existing sessions, deletes its API keys (the user creates
  new ones after signing in) and, with
  `OIDC_DISABLE_PASSWORD_LOGIN=true`, removes its password.
- If there is no such account, one is created with a verified email
  address and no password. `DISABLE_REGISTRATION` does not apply to
  these accounts: who may log in is decided by the provider's roles and
  `OIDC_ROLE_MAP`.

While single sign-on is enabled, email addresses cannot be changed in
the account settings; the provider owns them.

Because of that first link by email address, anyone who could create a
verified account here before the address's owner first signs in through
the provider could take over that link. Keep registration closed
(`DISABLE_REGISTRATION=true`) and create accounts only through the
provider or the `create-user` task.

Before enabling single sign-on on an instance that already has accounts,
review accounts whose email address was changed while email
verification was off (`ENABLE_EMAIL_VERIFICATION=false`). Such a change
takes effect without proof that the user owns the new address, and the
first single sign-on by that address's owner links to the account.

Bindings record the issuer. Changing `OIDC_ISSUER` (for example moving
to another provider or realm) leaves accounts bound to the old issuer,
and their logins are refused until they are bound again. The
`oidc-binding` task sets or clears an account's binding. A change ends
the account's sessions; passwords and API keys are kept. Running it
again with the same values changes nothing. `rebind` accepts only the
issuer currently configured in `OIDC_ISSUER`, so set the new issuer
first:

| Variable | Value |
|---|---|
| `OIDC_BINDING_EMAIL` | Email address of the account. |
| `OIDC_BINDING_ACTION` | `clear` to remove the binding (the next single sign-on links the account again by email, under the conditions above), or `rebind` to bind it to the identity below. |
| `OIDC_BINDING_ISSUER` | For `rebind`: the provider's `iss` value; must equal `OIDC_ISSUER`. |
| `OIDC_BINDING_SUBJECT` | For `rebind`: the user's `sub` value at the provider. |

```sh
docker run --rm --env-file app.env \
  -e OIDC_BINDING_EMAIL=user@example.com -e OIDC_BINDING_ACTION=clear \
  -v "$PWD/client-secret:/run/secrets/oidc-client-secret:ro" \
  ghcr.io/muutto365/avora-analytics:sha-<commit> db oidc-binding
```

The example assumes `OIDC_CLIENT_SECRET_FILE=/run/secrets/oidc-client-secret`
in `app.env`; like every one-off command, the task needs the same OIDC
settings and secret file as the application. Inside a running container
the same task is `/app/oidc-binding.sh`.

### Roles

Access comes from the provider's **client roles** on this
application's client (typically assigned through groups), mapped by
`OIDC_ROLE_MAP` and applied at every sign-in:

- Only a person holding at least one mapped role can sign in. A role the
  map does not name grants nothing, and there is no setting that lets
  anyone in.
- The role applies to the **managed team**: the team owned by the
  `PROVISIONING_OWNER_EMAIL` account, which holds the provisioned sites.
  The highest mapped role wins (`admin` over `editor` over `viewer`). A
  first sign-in adds the person to that team; a later sign-in with
  another role changes it. The team's owner is never changed. Without a
  configured provisioning owner, roles are still required to sign in but
  no team membership is set.
- A bound account that signs in without any mapped role is refused, is
  removed from the managed team and loses its sessions.
- While the map is in use, the managed team's members, roles and
  invitations, and guest access to its sites, cannot be changed in the
  team or site settings: the provider is the only source. Other teams are
  unaffected.
- Each change is recorded as a `role.sync` audit record (see "Audit
  records").

`OIDC_ROLE_MAP` replaces the earlier group check: `OIDC_ALLOWED_GROUPS`
and `OIDC_GROUPS_CLAIM` are no longer read, and setting either stops the
application at startup, so a configuration written for the group check
cannot start with access silently changed.

### Sessions and two-factor authentication

A session started through single sign-on ends after
`OIDC_SESSION_HOURS`, however active it is. The user then signs in again
through the provider, which checks again that the account is enabled,
and the role is applied again. Removing a user or their role at the
provider therefore takes effect at the latest when their session ends. API keys the user created
are not tied to the session and keep working until they are deleted
here. Logging out ends the session here only, not at the provider.

Multi-factor authentication is left to the provider. An account that
has its own two-factor authentication enabled here is still asked for
its code after the provider has signed it in. For sessions started
through single sign-on, a team's "require 2FA" setting counts as
satisfied by the provider, and users are not asked to set up two-factor
authentication here.

### Single sign-on only

With `OIDC_DISABLE_PASSWORD_LOGIN=true` the login page shows only the
single sign-on button. The password login, password reset and the
two-factor step after a password are refused, and registration is
disabled whatever `DISABLE_REGISTRATION` says. There is no other way in
while the setting is on; to recover from a provider outage, unset it and
restart.

## Audit records

Administrative actions are recorded as audit records, one JSON object
per line, in the file named by `AUDIT_LOG_FILE` (an absolute path; unset
means no file is written). A log collector running next to the
application is expected to ship the file; the application itself sends
nothing over the network.

- **What is recorded:** sites created or deleted (through the
  provisioning API or the dashboard), team role changes, removals and
  invitations, site invitations, API keys created or deleted, CSV
  exports (downloads from the dashboard, scheduled exports and their
  downloads), and changes to an account's single sign-on binding (at the
  first sign-in or by the `oidc-binding` task). Sign-ins themselves are
  left to the identity provider.
- **Fields:** `time`, `event.name` (`loop.audit`), `audit.schema` (1),
  `audit.event_id`, `audit.source` (`avora-analytics`), `audit.action`,
  `audit.outcome`, optional `audit.reason`, `principal.kind` and
  `principal.id`, optional `loop.org`, `target.type` and `target.id`,
  optional `avora.role`, `avora.previous_role` and `avora.via`, and the
  trace ids when there is a trace. Every value is checked against its
  shape and left out when it does not match.
- **No personal data:** a person is recorded only as `oidc:<subject>`
  (the identity provider's subject identifier, when it is a UUID and the
  account is bound to the configured issuer) or as `unbound`. No names,
  email addresses, domains or free text; sites, teams and API keys are
  recorded by numeric id.
- **Best effort:** the Community Edition has no audit table, so the file
  is the only copy until it is shipped. Each record is flushed and synced
  before the action returns, and a failed write never fails the action.
  The file rotates at 10 MB and keeps five archives
  (`<file>.0` … `<file>.4`).

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
