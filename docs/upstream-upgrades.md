# Upgrading to a new upstream release

This repository is a source snapshot of
[Plausible Analytics](https://github.com/plausible/analytics) Community
Edition with our changes on top. It does not contain upstream's git
history. [`UPSTREAM`](../UPSTREAM) records the tag and commit the tree is
based on.

Upstream's history includes code under `extra/` and
`assets/js/dashboard/extra/` that is not licensed for redistribution.
That code must never enter this repository, so an upgrade is applied as a
tag-to-tag diff with those paths left out, never as a merge or a fetch of
upstream history into this repository.

## How we learn about a new release

The [Upstream check](../.github/workflows/upstream.yml) workflow runs
daily. It keeps one open issue labelled `upstream` that lists:

- release tags newer than the one in `UPSTREAM`, with links to the release
  notes and to the upstream compare view (`vOLD...vNEW`);
- for each new tag, the locked Hex and npm packages whose version differs
  from ours and that have known advisories at our version;
- upstream security advisories whose affected range includes our version.

It only reads public metadata and never changes the code. The issue is
closed when there is nothing left to report.

## Applying an upgrade

Work in a scratch directory **outside** this repository. Never add
upstream as a remote of this repository and never push from the upstream
clone.

```sh
OLD=v3.2.1   # the tag in UPSTREAM
NEW=v3.3.0   # the release to move to

git clone --filter=blob:none --no-checkout https://github.com/plausible/analytics upstream
git -C upstream diff --binary "$OLD" "$NEW" -- . \
  ':(exclude,glob)**/extra/**' \
  ':(exclude)extra' \
  ':(exclude)assets/js/dashboard/extra' \
  ':(exclude).github' \
  > upgrade.patch

# The patch must not touch any path named "extra".
if grep -E '^diff --git a/(.*/)?extra/' upgrade.patch; then
  echo "patch touches excluded paths" >&2
fi

git -C upstream rev-parse "$NEW^{commit}"   # the commit for UPSTREAM
```

Then, in this repository:

```sh
git switch -c upgrade/$NEW origin/main
git apply --3way --index /path/to/upgrade.patch
```

1. Resolve conflicts with our changes. `git apply --3way` leaves conflict
   markers where upstream changed lines we also changed.
2. Check the files listed in `UPSTREAM` as modified on import (for
   example the blanked credentials in `config/.env.dev` and
   `config/.env.load`). Keep our version.
3. Update `UPSTREAM` with the new tag and commit.
4. Run `.github/scripts/check-no-extra.sh` locally, then open a pull
   request. CI runs the same guard, the test suite and the security scans.
5. In the pull request description, link the upstream release notes and
   name any of our patches that had to change.

After the merge, the next upstream check closes the issue if nothing newer
remains.

## Dependency security fixes between upgrades

The [Security](../.github/workflows/security.yml) workflow audits
`mix.lock`, the npm lockfiles in `assets/` and `tracker/`, the source tree
and the built image. Its header documents which findings fail a pull
request. A finding that cannot be fixed yet can be accepted for at most
30 days in [`.github/security-baseline.yml`](../.github/security-baseline.yml),
with a reason; the gate fails when an entry expires or no longer matches a
finding. The daily run keeps one open issue labelled `security` with the
unresolved findings (baselined ones marked) and the git dependencies.

Dependabot proposes security updates for Hex and npm packages, and weekly
version updates for GitHub Actions and the Docker base images. Hex and
npm versions otherwise follow upstream's lockfiles. A security bump we
make ahead of upstream should stay within the version requirements in
`mix.exs` and `package.json` where possible, so the next upgrade diff
applies cleanly.
