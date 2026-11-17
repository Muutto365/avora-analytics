#!/usr/bin/env python3
"""Reports upstream releases and security advisories that concern the
upstream version this tree is based on (recorded in UPSTREAM), and newer
Alpine patch releases for the minor version the Dockerfile pins.

It only reads public metadata (tags, advisories and lockfiles at a tag,
held in memory) and writes one tracking issue. It never brings upstream
code into this repository; see docs/upstream-upgrades.md for how an
upgrade is applied.

Usage:
  upstream_watch.py [--dry-run] [--repo OWNER/NAME] [--pin-tag vX.Y.Z]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghutil  # noqa: E402

MARKER = "<!-- upstream-tracker -->"
TITLE = "Upstream: new releases, advisories or base image updates"
LABEL = "upstream"
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOCKFILES = {
    "mix.lock": "Hex",
    "assets/package-lock.json": "npm",
    "tracker/package-lock.json": "npm",
}


def read_upstream(path: str) -> dict:
    info = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^(repository|tag|commit):\s*(\S+)\s*$", line)
            if m:
                info[m.group(1)] = m.group(2)
    for key in ("repository", "tag", "commit"):
        if key not in info:
            raise SystemExit(f"error: UPSTREAM has no '{key}:' line")
    m = re.match(r"^https://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", info["repository"])
    if not m:
        raise SystemExit("error: UPSTREAM repository is not a GitHub URL")
    info["slug"] = m.group(1)
    return info


# ------------------------------------------------------------- lockfiles


_MIX_LINE = re.compile(r'^\s*"[^"]+":\s*\{:hex,\s*:([A-Za-z0-9_]+),\s*"([^"]+)"', re.M)


def parse_mix_lock(text: str) -> dict[str, set]:
    out: dict[str, set] = {}
    for name, ver in _MIX_LINE.findall(text):
        out.setdefault(name, set()).add(ver)
    return out


def parse_package_lock(text: str) -> dict[str, set]:
    data = json.loads(text)
    out: dict[str, set] = {}
    for path, meta in (data.get("packages") or {}).items():
        if not path or meta.get("link") or "node_modules/" not in path or not meta.get("version"):
            continue
        name = path.rsplit("node_modules/", 1)[1]
        out.setdefault(name, set()).add(meta["version"])
    return out


def parse_lock(path: str, text: str) -> dict[str, set]:
    return parse_mix_lock(text) if path.endswith("mix.lock") else parse_package_lock(text)


def diff_locks(ours: dict[str, set], theirs: dict[str, set]) -> list[tuple]:
    """(name, our versions, their versions) for every package that differs."""
    out = []
    for name in sorted(set(ours) | set(theirs)):
        a, b = ours.get(name, set()), theirs.get(name, set())
        if a != b:
            out.append((name, sorted(a, key=ghutil.version_key), sorted(b, key=ghutil.version_key)))
    return out


def osv_batch(queries: list[tuple]) -> list[list[str]]:
    """queries: (ecosystem, name, version) -> list of advisory ids each."""
    results: list[list[str]] = []
    for i in range(0, len(queries), 500):
        chunk = queries[i:i + 500]
        _, resp = ghutil.http("POST", "https://api.osv.dev/v1/querybatch", {"queries": [
            {"package": {"ecosystem": eco, "name": name}, "version": ver} for eco, name, ver in chunk]})
        if not isinstance(resp, dict) or len(resp.get("results", [])) != len(chunk):
            raise RuntimeError("unexpected OSV querybatch response")
        results += [sorted(v["id"] for v in (r.get("vulns") or [])) for r in resp["results"]]
    return results


def advisory_changes(tag: str, slug: str, fetch=None, osv=osv_batch) -> dict:
    """Packages whose locked version differs between our tree and `tag`,
    restricted to those where our version has known advisories."""
    fetch = fetch or (lambda path: ghutil.http(
        "GET", f"https://raw.githubusercontent.com/{slug}/{tag}/{path}", accept="*/*")[1])
    rows, changed_total = [], 0
    for path, eco in LOCKFILES.items():
        try:
            theirs = parse_lock(path, fetch(path))
        except ghutil.HttpError as e:
            if e.status == 404:
                continue
            raise
        with open(os.path.join(ROOT, path), encoding="utf-8") as f:
            ours = parse_lock(path, f.read())
        changes = diff_locks(ours, theirs)
        changed_total += len(changes)
        queries, index = [], []
        for name, a, b in changes:
            for v in a:
                queries.append((eco, name, v))
                index.append((name, "ours", v))
            for v in b:
                queries.append((eco, name, v))
                index.append((name, "theirs", v))
        found: dict = {}
        for (name, side, v), ids in zip(index, osv(queries) if queries else []):
            found.setdefault(name, {"ours": {}, "theirs": {}})[side][v] = ids
        for name, a, b in changes:
            ours_ids = sorted({i for v in a for i in found.get(name, {}).get("ours", {}).get(v, [])})
            if not ours_ids:
                continue
            theirs_ids = {i for v in b for i in found.get(name, {}).get("theirs", {}).get(v, [])}
            rows.append({
                "file": path, "package": name, "ours": a, "theirs": b,
                "advisories": ours_ids,
                "resolved": [i for i in ours_ids if i not in theirs_ids],
            })
    return {"changed": changed_total, "rows": rows}


# ------------------------------------------------------------ advisories


def advisory_status(adv: dict, version: str) -> str:
    """'yes', 'no' or 'unknown' for whether `version` is affected."""
    verdicts = []
    for v in adv.get("vulnerabilities") or []:
        verdicts.append(ghutil.in_range(version, v.get("vulnerable_version_range") or ""))
    if any(x is True for x in verdicts):
        return "yes"
    if verdicts and all(x is False for x in verdicts):
        return "no"
    return "unknown"


# ------------------------------------------------------------------ main


# ---------------------------------------------------------------- alpine


def alpine_status(dockerfile: str, releases_json=None, tag_exists=None) -> dict | None:
    """Latest Alpine patch release for the minor version the Dockerfile
    pins, and whether a builder image tag exists for it."""
    with open(dockerfile, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^ARG ALPINE_VERSION=(\d+)\.(\d+)\.(\d+)\s*$", text, re.M)
    if not m:
        return None
    pinned = ".".join(m.groups())
    data = releases_json if releases_json is not None else ghutil.get_json("https://alpinelinux.org/releases.json")
    branch = next((b for b in data.get("release_branches", [])
                   if b.get("rel_branch") == f"v{m.group(1)}.{m.group(2)}"), None)
    if branch is None:
        raise RuntimeError(f"Alpine branch v{m.group(1)}.{m.group(2)} not found in releases.json")
    versions = [r["version"] for r in branch.get("releases", []) if re.fullmatch(r"\d+\.\d+\.\d+", r.get("version", ""))]
    latest = max(versions + [pinned], key=ghutil.version_key)
    res = {"pinned": pinned, "latest": latest, "eol": branch.get("eol_date"),
           "builder": None, "builder_available": None}
    b = re.search(r"^FROM (hexpm/elixir):(\S+)-alpine-\$\{ALPINE_VERSION\}", text, re.M)
    if b and latest != pinned:
        tag = f"{b.group(2)}-alpine-{latest}"
        res["builder"] = f"{b.group(1)}:{tag}"
        if tag_exists is None:
            try:
                ghutil.get_json(f"https://hub.docker.com/v2/repositories/{b.group(1)}/tags/{tag}")
                res["builder_available"] = True
            except ghutil.HttpError as e:
                if e.status != 404:
                    raise
                res["builder_available"] = False
        else:
            res["builder_available"] = tag_exists(tag)
    return res


def collect(info: dict, pin: str) -> dict:
    slug = info["slug"]
    # Version tags only; the plain tag listing also holds hundreds of
    # rolling "r..." tags. This endpoint is not paginated.
    refs = ghutil.get_json(f"{ghutil.GITHUB_API}/repos/{slug}/git/matching-refs/tags/v")
    tags = [r["ref"][len("refs/tags/"):] for r in refs if r.get("ref", "").startswith("refs/tags/")]
    newer = sorted({t for t in tags if ghutil.is_stable_tag(t) and ghutil.vcmp(t, pin) > 0},
                   key=ghutil.version_key)
    releases = []
    for tag in newer:
        releases.append({"tag": tag, **advisory_changes(tag, slug)})
    advisories = ghutil.get_json(
        f"{ghutil.GITHUB_API}/repos/{slug}/security-advisories?state=published&per_page=100")
    advs = []
    for a in advisories:
        advs.append({
            "id": a.get("ghsa_id"), "cve": a.get("cve_id"), "url": a.get("html_url"),
            "severity": a.get("severity"), "summary": a.get("summary"),
            "published": a.get("published_at"),
            "ranges": [v.get("vulnerable_version_range") for v in a.get("vulnerabilities") or []],
            "patched": [v.get("patched_versions") for v in a.get("vulnerabilities") or []],
            "status": advisory_status(a, pin.lstrip("v")),
        })
    return {"slug": slug, "pin": pin, "commit": info["commit"], "releases": releases, "advisories": advs,
            "alpine": alpine_status(os.path.join(ROOT, "Dockerfile"))}


def render(report: dict, now: str | None = None) -> str | None:
    relevant = [a for a in report["advisories"] if a["status"] != "no"]
    alpine = report.get("alpine")
    alpine_new = bool(alpine and alpine["latest"] != alpine["pinned"])
    if not report["releases"] and not relevant and not alpine_new:
        return None
    now = now or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    slug, pin = report["slug"], report["pin"]
    base = f"https://github.com/{slug}"
    lines = [MARKER,
             f"Upstream check for `{slug}` against our base `{pin}` "
             f"(`{report['commit'][:12]}`), updated {now}.", ""]
    if report["releases"]:
        lines += [f"### New upstream releases ({len(report['releases'])})", ""]
        for r in report["releases"]:
            lines.append(f"- **{ghutil.md_text(r['tag'])}**: "
                         f"[release notes]({base}/releases/tag/{r['tag']}), "
                         f"[changes since {pin}]({base}/compare/{pin}...{r['tag']}). "
                         f"{r['changed']} locked package versions differ from ours; "
                         f"{len(r['rows'])} of them have known advisories at our version.")
            if r["rows"]:
                lines += ["", "  | File | Package | Ours | Theirs | Advisories at our version | Not present at theirs |",
                          "  |---|---|---|---|---|---|"]
                for row in r["rows"]:
                    lines.append("  | " + " | ".join([
                        ghutil.md_text(row["file"]), ghutil.md_code(row["package"]),
                        ghutil.md_text(", ".join(row["ours"]) or "-"),
                        ghutil.md_text(", ".join(row["theirs"]) or "removed"),
                        ", ".join(ghutil.md_link(i, f"https://osv.dev/vulnerability/{i}") for i in row["advisories"][:6])
                        + (" ..." if len(row["advisories"]) > 6 else ""),
                        str(len(row["resolved"])),
                    ]) + " |")
                lines.append("")
        lines += ["", f"To upgrade, follow [docs/upstream-upgrades.md](https://github.com/{report['repo']}/blob/main/docs/upstream-upgrades.md).", ""]
    if relevant:
        lines += [f"### Upstream security advisories affecting {pin} ({len(relevant)})", "",
                  "| Advisory | Severity | Summary | Affected | Patched | Affects us |",
                  "|---|---|---|---|---|---|"]
        for a in relevant:
            lines.append("| " + " | ".join([
                ghutil.md_link(a["id"], a["url"]) + (f" ({ghutil.md_text(a['cve'])})" if a["cve"] else ""),
                ghutil.md_text((a["severity"] or "").upper()), ghutil.md_text(a["summary"]),
                ghutil.md_text("; ".join(r or "?" for r in a["ranges"])),
                ghutil.md_text("; ".join(p or "?" for p in a["patched"])),
                "yes" if a["status"] == "yes" else "needs review (range not machine-readable)",
            ]) + " |")
        lines.append("")
    if alpine_new:
        builder = ""
        if alpine["builder"]:
            builder = (f" The builder image `{alpine['builder']}` "
                       + ("exists." if alpine["builder_available"] else "is not published yet."))
        lines += ["### Alpine base image", "",
                  f"The Dockerfile pins Alpine `{alpine['pinned']}`; the latest patch release of that minor "
                  f"version is `{alpine['latest']}` (branch end of life {alpine['eol'] or 'unknown'}).{builder} "
                  + ("Update `ALPINE_VERSION` in the Dockerfile."
                     if alpine["builder_available"] is not False else
                     "The builder and runtime stages share `ALPINE_VERSION`, so either wait for the builder "
                     "image or pin the stages separately."), ""]
    not_affecting = len(report["advisories"]) - len(relevant)
    if not_affecting:
        lines.append(f"{not_affecting} other published upstream advisories do not affect {pin}.")
    url = ghutil.run_url()
    if url:
        lines.append(f"Report from [this workflow run]({url}).")
    lines.append("This issue is maintained by the upstream check workflow: it is updated in place "
                 "and closed when there is nothing new to report.")
    return ghutil.cap_body("\n".join(lines) + "\n")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="print the plan and body, change nothing")
    p.add_argument("--repo", help="repository that holds the tracking issue (default: GITHUB_REPOSITORY)")
    p.add_argument("--upstream-file", default=os.path.join(ROOT, "UPSTREAM"))
    p.add_argument("--pin-tag", help="dry-run only: compare against this tag instead of UPSTREAM's")
    p.add_argument("--simulate-open-issue", type=int, metavar="NUMBER",
                   help="dry-run only: pretend this tracking issue is open")
    a = p.parse_args(argv)
    if (a.pin_tag or a.simulate_open_issue) and not a.dry_run:
        p.error("--pin-tag and --simulate-open-issue need --dry-run")
    repo = a.repo or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        p.error("--repo or GITHUB_REPOSITORY is required")
    info = read_upstream(a.upstream_file)
    pin = a.pin_tag or info["tag"]
    report = collect(info, pin)
    report["repo"] = repo
    body = render(report)
    existing = ghutil.find_open_issues(repo, LABEL, MARKER)
    if a.simulate_open_issue:
        existing = [{"number": a.simulate_open_issue, "body": MARKER + "\n(simulated)"}]
    actions = ghutil.plan_issue(existing, body, "No new upstream releases or advisories affecting "
                                f"{pin} remain. Closing.")
    print(f"pin {pin}: {len(report['releases'])} newer release tag(s), "
          f"{len(report['advisories'])} published advisories "
          f"({sum(1 for x in report['advisories'] if x['status'] == 'yes')} affecting, "
          f"{sum(1 for x in report['advisories'] if x['status'] == 'unknown')} need review)")
    if a.dry_run:
        print(f"[dry-run] open tracking issues: {[i['number'] for i in existing]}")
        print("----- body -----")
        print(body if body is not None else "(none: nothing to report)")
    ghutil.apply_issue_actions(repo, actions, TITLE, LABEL, "0e8a16",
                               "Upstream releases and advisories to review", a.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())
