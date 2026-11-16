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
