#!/usr/bin/env python3
"""Reports the git dependencies locked in mix.lock, which the Hex advisory
tools do not cover: the pinned commit against the branch it tracks (or
the repository's default branch), the security advisories published on
each GitHub repository (and on its parent, for forks), and OSV advisories
for the Hex package of the same name at the version in the pinned
commit's mix.exs.

Usage: git_deps.py [--lock mix.lock] --out git-deps.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghutil  # noqa: E402

_GIT = re.compile(r'^\s*"([^"]+)":\s*\{:git,\s*"([^"]+)",\s*"([0-9a-f]{7,40})",\s*\[([^\]]*)\]', re.M)


def parse_git_deps(lock_text: str) -> list[dict]:
    out = []
    for name, url, sha, opts in _GIT.findall(lock_text):
        branch = re.search(r'branch:\s*"([^"]+)"', opts)
        ref = re.search(r'(?:ref|tag):\s*"([^"]+)"', opts)
        out.append({"name": name, "url": url, "sha": sha,
                    "branch": branch.group(1) if branch else None,
                    "ref": ref.group(1) if ref else None})
    return out


def github_slug(url: str):
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


_VERSION = re.compile(r'(?:@version\s+"|\bversion:\s*")(\d+\.\d+\.\d+[^"]*)"')


def pinned_version(slug: str, sha: str):
    try:
        text = ghutil.http("GET", f"https://raw.githubusercontent.com/{slug}/{sha}/mix.exs", accept="*/*")[1]
    except ghutil.HttpError as e:
        if e.status == 404:
            return None
        raise
    m = _VERSION.search(text)
    return m.group(1) if m else None


def repo_advisories(slug: str, version) -> list[dict]:
    out = []
    for a in ghutil.get_json(f"{ghutil.GITHUB_API}/repos/{slug}/security-advisories?state=published&per_page=100"):
        ranges = [v.get("vulnerable_version_range") or "" for v in a.get("vulnerabilities") or []]
        verdicts = [ghutil.in_range(version, r) for r in ranges] if version else []
        affects = "yes" if True in verdicts else "no" if verdicts and all(v is False for v in verdicts) else "unknown"
        out.append({"id": a.get("ghsa_id"), "url": a.get("html_url"), "severity": a.get("severity") or "?",
                    "summary": a.get("summary"), "range": "; ".join(ranges), "affects": affects,
                    "source": slug})
    return out


def osv_advisories(name: str, version) -> list[dict]:
    if not version:
        return []
    _, resp = ghutil.http("POST", "https://api.osv.dev/v1/query",
                          {"package": {"ecosystem": "Hex", "name": name}, "version": version})
    return [{"id": v["id"], "url": f"https://osv.dev/vulnerability/{v['id']}", "severity": "see advisory",
             "summary": v.get("summary", ""), "range": "", "affects": "yes", "source": "OSV (Hex)",
             "aliases": v.get("aliases") or []}
            for v in (resp or {}).get("vulns", [])]


def check(dep: dict) -> dict:
    slug = github_slug(dep["url"])
    res = dict(dep, repo=slug or dep["url"], url=f"https://github.com/{slug}" if slug else dep["url"],
               compared_with=None, behind_by=None, advisories=None, version=None)
    if not slug:
        return res
    api = f"{ghutil.GITHUB_API}/repos/{slug}"
    repo = ghutil.get_json(api)
    target = dep["branch"] or repo["default_branch"]
    res["compared_with"] = f"{target} ({'tracked branch' if dep['branch'] else 'default branch'})"
    try:
        cmp = ghutil.get_json(f"{api}/compare/{dep['sha']}...{target}")
        res["behind_by"] = cmp.get("ahead_by")
    except ghutil.HttpError as e:
        if e.status not in (404, 422):
            raise
        res["compared_with"] += ", not comparable (branch or commit gone)"
    res["version"] = pinned_version(slug, dep["sha"])
    advs = repo_advisories(slug, res["version"])
    if repo.get("fork") and repo.get("parent"):
        advs += repo_advisories(repo["parent"]["full_name"], res["version"])
    seen = {a["id"] for a in advs}
    advs += [a for a in osv_advisories(dep["name"], res["version"])
             if a["id"] not in seen and not seen & set(a["aliases"])]
    res["advisories"] = advs
    return res


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--lock", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "mix.lock"))
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    with open(a.lock, encoding="utf-8") as f:
        deps = parse_git_deps(f.read())
    results = [check(d) for d in deps]
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump({"git_deps": results}, f, indent=1)
    for r in results:
        relevant = [x for x in r["advisories"] or [] if x["affects"] != "no"]
        print(f"{r['name']:20} {r['version'] or '?':10} {r['sha'][:12]} vs {r['compared_with']}: "
              f"behind {r['behind_by']}, {len(r['advisories'] or [])} advisories, {len(relevant)} may affect it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
