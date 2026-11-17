#!/usr/bin/env python3
"""Collects dependency and image vulnerability findings into one list,
applies the build-failure rule, and keeps one tracking issue up to date.

Subcommands:
  collect  parse scanner outputs, resolve fixed versions, write findings JSON
  gate     exit 1 if the findings break the rule below
  render   print the issue body (or the "clean" result)
  issue    create / update / close the tracking issue (supports --dry-run)

Inputs are validated strictly: a missing or malformed scanner output is an
error, never an empty result, so a scanner outage cannot close the issue.

npm findings include dev dependencies and are marked build-time.

Failure rule (also documented in .github/workflows/security.yml):
  a finding fails the gate when its severity is CRITICAL or HIGH and a
  fixed version exists, or when a Hex package is retired for security
  reasons, unless .github/security-baseline.yml accepts it. The gate
  also fails on a baseline entry that is incomplete, past its review_by
  date, more than 30 days out, or that matches no current finding.
  Everything else is reported but does not fail the build.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghutil  # noqa: E402

MARKER = "<!-- security-tracker -->"
TITLE = "Security: unresolved vulnerability findings"
LABEL = "security"
SEVERITIES = ["critical", "high", "medium", "low", "unknown"]


class InputError(Exception):
    pass


def norm_sev(s) -> str:
    s = str(s or "").strip().lower()
    return {"moderate": "medium", "negligible": "low", "info": "low"}.get(s, s if s in SEVERITIES else "unknown")


def sev_from_score(score) -> str:
    try:
        x = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if x >= 9.0:
        return "critical"
    if x >= 7.0:
        return "high"
    if x >= 4.0:
        return "medium"
    if x > 0:
        return "low"
    return "unknown"


def finding(*, source, location, package, installed, ids, severity, url="",
            title="", fixed_candidates=(), kind="advisory", fix_hint=None):
    ids = [i for i in ids if i]
    return {
        "kind": kind,
        "sources": [source],
        "locations": [location],
        "package": package,
        "installed": installed,
        "ids": list(dict.fromkeys(ids)),
        "severity": norm_sev(severity),
        "url": url,
        "title": title,
        "fixed_candidates": [c for c in fixed_candidates if c],
        "fix_hint": fix_hint,
        "fixed": None,
        "build_time": False,
    }


# ---------------------------------------------------------------- parsers


def _load(path: str):
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        raise InputError(f"{path}: missing or empty")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise InputError(f"{path}: not JSON ({e})")


def parse_mix_audit(path: str) -> list[dict]:
    data = _load(path)
    if not isinstance(data, dict) or "pass" not in data or not isinstance(data.get("vulnerabilities"), list):
        raise InputError(f"{path}: not a mix_audit JSON report")
    out = []
    for v in data["vulnerabilities"]:
        dep, adv = v["dependency"], v["advisory"]
        out.append(finding(
            source="mix_audit", location="mix.lock", package=dep["package"],
            installed=dep["version"], ids=[adv.get("id"), adv.get("cve")],
            severity=adv.get("severity"), url=adv.get("url", ""),
            title=adv.get("title", ""),
            fixed_candidates=adv.get("first_patched_versions") or []))
    return out


_AKA = re.compile(r"^\s*(\S+)(?:\s*\(aka\s*([^)]*)\))?\s*$")


def parse_hex_sarif(path: str) -> list[dict]:
    data = _load(path)
    runs = data.get("runs") if isinstance(data, dict) else None
    if not isinstance(runs, list) or not runs:
        raise InputError(f"{path}: not a SARIF report")
    out = []
    for run in runs:
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId"), {})
            args = res.get("message", {}).get("arguments") or []
            fp = next(iter((res.get("partialFingerprints") or {}).values()), "")
            text = res.get("message", {}).get("text", "")
            if fp.startswith("advisory:") and len(args) >= 5:
                m = _AKA.match(args[2])
                ids = [m.group(1)] + ([a.strip() for a in m.group(2).split(",")] if m and m.group(2) else []) \
                    if m else [res.get("ruleId")]
                out.append(finding(
                    source="hex.audit", location="mix.lock", package=args[0], installed=args[1],
                    ids=ids, severity=sev_from_score(rule.get("properties", {}).get("security-severity")),
                    url=args[4], title=args[3]))
            else:
                # Retirements and any other finding type: kept generic.
                pkg = args[0] if args else res.get("ruleId", "?")
                ver = args[1] if len(args) > 1 else ""
                security = "security" in text.lower()
                out.append(finding(
                    source="hex.audit", location="mix.lock", package=pkg, installed=ver,
                    ids=[res.get("ruleId") or "hex-finding"],
                    severity="high" if security else "unknown",
                    url=rule.get("helpUri", ""), title=text, kind="retired",
                    fix_hint=True))
    return out


def _lock_packages(lock_path: str) -> dict:
    """node path -> (version, dev) from package-lock.json; dev covers
    packages only reachable from devDependencies (build-time only)."""
    with open(lock_path, encoding="utf-8") as f:
        lock = json.load(f)
    return {k: (v.get("version"), bool(v.get("dev") or v.get("devOptional")))
            for k, v in (lock.get("packages") or {}).items()}


def npm_range(rng: str) -> str:
    """npm range syntax to the comparator list in_range() reads:
    ">=4.0.0 <4.0.4" -> ">=4.0.0, <4.0.4"; "6.0.0 - 7.17.0" -> ">=6.0.0, <=7.17.0"."""
    m = re.fullmatch(r"\s*(\S+)\s+-\s+(\S+)\s*", rng)
    if m:
        return f">={m.group(1)}, <={m.group(2)}"
    rng = re.sub(r"(>=|<=|>|<|=)\s+", r"\1", rng)
    return ", ".join(rng.split()).replace(",, ", ", ").replace("||,", "||").replace(", ||", " ||")


def parse_npm_audit(path: str, location: str, lockfile: str) -> list[dict]:
    data = _load(path)
    if not isinstance(data, dict) or "error" in data or "vulnerabilities" not in data \
            or data.get("auditReportVersion") != 2:
        raise InputError(f"{path}: not an npm audit v2 JSON report ({str(data.get('error'))[:200] if isinstance(data, dict) else ''})")
    packages = _lock_packages(lockfile)
    out = []
    for name, vuln in data["vulnerabilities"].items():
        nodes = [packages[n] for n in vuln.get("nodes", []) if n in packages and packages[n][0]]
        installed = sorted({v for v, _ in nodes}, key=ghutil.version_key)
        # a version counts as build-time only when every copy of it is a dev dependency
        build_time = {v: all(dev for ver, dev in nodes if ver == v) for v in installed}
        for via in vuln.get("via", []):
            if not isinstance(via, dict):
                continue  # vulnerable only through another listed package
            url = via.get("url", "")
            ghsa = url.rsplit("/", 1)[-1] if "/advisories/GHSA-" in url else None
            for ver in installed or ["?"]:
                if ver != "?" and ghutil.in_range(ver, npm_range(via.get("range") or "")) is False:
                    continue  # this advisory does not cover this copy
                dev = build_time.get(ver, False)
                f = finding(
                    source="npm audit", location=f"{location} (build-time)" if dev else location,
                    package=via.get("name") or name,
                    installed=ver, ids=[ghsa or f"npm-{via.get('source')}"],
                    severity=via.get("severity") or vuln.get("severity"), url=url,
                    title=via.get("title", ""),
                    fix_hint=bool(vuln.get("fixAvailable")))
                f["build_time"] = dev
                out.append(f)
    return out


def parse_trivy(path: str, label: str) -> list[dict]:
    data = _load(path)
    if not isinstance(data, dict) or "SchemaVersion" not in data:
        raise InputError(f"{path}: not a Trivy JSON report")
    out = []
    for res in data.get("Results") or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            fixed = [x.strip() for x in (v.get("FixedVersion") or "").split(",")]
            out.append(finding(
                source=f"trivy {label}", location=target if label == "fs" else f"{label}: {target}", package=v.get("PkgName", "?"),
                installed=v.get("InstalledVersion", "?"), ids=[v.get("VulnerabilityID")],
                severity=v.get("Severity"), url=v.get("PrimaryURL", ""),
                title=v.get("Title", ""), fixed_candidates=fixed))
    return out


# ---------------------------------------------------------- enrichment


def osv_lookup(vid: str) -> dict:
    return ghutil.get_json(f"https://api.osv.dev/v1/vulns/{vid}")


def ghsa_lookup(ghsa: str) -> dict:
    return ghutil.get_json(f"{ghutil.GITHUB_API}/advisories/{ghsa}")


def fixed_from_osv(rec: dict, package: str, installed: str) -> list[str]:
    fixes = []
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name", "").lower() != package.lower():
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            intro = None
            for ev in rng.get("events") or []:
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    lo_ok = intro in (None, "0") or ghutil.vcmp(installed, intro) >= 0
                    if lo_ok and ghutil.vcmp(installed, ev["fixed"]) < 0:
                        fixes.append(ev["fixed"])
    return fixes


def enrich(findings: list[dict], osv=osv_lookup, ghsa=ghsa_lookup) -> None:
    """Adds aliases and fixed-version candidates from OSV (Hex) and the
    GitHub advisory database (npm). Lookup errors propagate."""
    cache: dict = {}
    for f in findings:
        if f["kind"] != "advisory" or f["fixed_candidates"]:
            continue
        primary = f["ids"][0]
        if f["sources"][0] == "hex.audit":
            if ("osv", primary) not in cache:
                cache[("osv", primary)] = osv(primary)
            rec = cache[("osv", primary)]
            f["ids"] = list(dict.fromkeys(f["ids"] + (rec.get("aliases") or [])))
            f["fixed_candidates"] = fixed_from_osv(rec, f["package"], f["installed"])
        elif f["sources"][0] == "npm audit" and primary.startswith("GHSA-"):
            if ("ghsa", primary) not in cache:
                cache[("ghsa", primary)] = ghsa(primary)
            rec = cache[("ghsa", primary)]
            if rec.get("cve_id"):
                f["ids"].append(rec["cve_id"])
            for v in rec.get("vulnerabilities") or []:
                if (v.get("package") or {}).get("name") == f["package"] and v.get("first_patched_version"):
                    rng = v.get("vulnerable_version_range") or ""
                    if f["installed"] == "?" or ghutil.in_range(f["installed"], rng) is not False:
                        f["fixed_candidates"].append(v["first_patched_version"])


def pick_fixed(installed: str, candidates: list[str]):
    """The lowest candidate above the installed version, preferring the
    installed major line."""
    above = sorted({c for c in candidates if installed == "?" or ghutil.vcmp(c, installed) > 0},
                   key=ghutil.version_key)
    if not above:
        return None
    major = installed.lstrip("v").split(".")[0]
    same = [c for c in above if c.lstrip("v").split(".")[0] == major]
    return (same or above)[0]


def merge(findings: list[dict]) -> list[dict]:
    """Merges reports of the same advisory on the same package version
    from different tools (matched on any shared id or alias)."""
    merged: list[dict] = []
    for f in findings:
        target = None
        for m in merged:
            if m["package"].lower() == f["package"].lower() and m["installed"] == f["installed"] \
                    and m["kind"] == f["kind"] and set(m["ids"]) & set(f["ids"]):
                target = m
                break
        if target is None:
            merged.append(json.loads(json.dumps(f)))
            continue
        for key in ("sources", "locations", "ids", "fixed_candidates"):
            target[key] = list(dict.fromkeys(target[key] + f[key]))
        if SEVERITIES.index(f["severity"]) < SEVERITIES.index(target["severity"]):
            target["severity"] = f["severity"]
        target["fix_hint"] = target["fix_hint"] or f["fix_hint"]
        target["build_time"] = bool(target.get("build_time")) and bool(f.get("build_time"))
        if not target["url"]:
            target["url"] = f["url"]
        if not target["title"]:
            target["title"] = f["title"]
    for m in merged:
        m["fixed"] = pick_fixed(m["installed"], m["fixed_candidates"])
        m["fix_available"] = bool(m["fixed"]) or bool(m["fix_hint"])
        # prefer a GHSA/EEF/CVE id as the displayed one, in that order
        m["ids"].sort(key=lambda i: (0 if i.startswith("GHSA-") else 1 if i.startswith("EEF-") else 2 if i.startswith("CVE-") else 3, i))
    merged.sort(key=lambda m: (SEVERITIES.index(m["severity"]), not m["fix_available"], m["package"].lower(), m["ids"][0]))
    return merged


# ---------------------------------------------------------------- policy

BASELINE_MAX_DAYS = 30
DEFAULT_BASELINE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security-baseline.yml")


def failing(findings: list[dict]) -> list[dict]:
    """Findings the rule applies to, before the baseline is considered."""
    out = []
    for f in findings:
        if f["kind"] == "retired":
            if f["severity"] == "high":  # retired for security reasons
                out.append(f)
        elif f["severity"] in ("critical", "high") and f["fix_available"]:
            out.append(f)
    return out


def load_baseline(path: str) -> list[dict]:
    if not os.path.isfile(path):
        raise InputError(f"{path}: baseline file missing")
    with open(path, encoding="utf-8") as f:
        try:
            return ghutil.parse_entry_list(f.read())
        except ValueError as e:
            raise InputError(f"{path}: {e}")


def apply_baseline(findings: list[dict], entries: list[dict], today: date) -> list[str]:
    """Marks baselined findings (f["baseline"]) and returns the problems
    with the baseline itself: invalid, expired, too far out, or stale."""
    problems = []
    for f in findings:
        f.pop("baseline", None)
    for n, e in enumerate(entries, 1):
        label = f"entry {n} ({e.get('package', '?')} {e.get('id', '?')})"
        missing = [k for k in ("id", "package", "reason", "review_by") if not e.get(k)]
        if missing:
            problems.append(f"{label}: missing {', '.join(missing)}")
            continue
        try:
            review_by = date.fromisoformat(e["review_by"])
        except ValueError:
            problems.append(f"{label}: review_by is not a YYYY-MM-DD date")
            continue
        if review_by < today:
            problems.append(f"{label}: review_by {review_by} has passed; review the entry and fix or renew it")
        elif review_by > today + timedelta(days=BASELINE_MAX_DAYS):
            problems.append(f"{label}: review_by {review_by} is more than {BASELINE_MAX_DAYS} days out")
        matched = [f for f in findings
                   if f["package"].lower() == e["package"].lower() and e["id"] in f["ids"]]
        if not matched:
            problems.append(f"{label}: matches no current finding; remove it")
        for f in matched:
            f["baseline"] = {"review_by": e["review_by"], "reason": e["reason"], "id": e["id"]}
    return problems


def gate_result(findings: list[dict], entries: list[dict], today: date):
    problems = apply_baseline(findings, entries, today)
    blocking = [f for f in failing(findings) if "baseline" not in f]
    return blocking, problems


# ---------------------------------------------------------------- render


def advisory_link(f: dict) -> str:
    primary = f["ids"][0]
    url = f["url"]
    if primary.startswith("GHSA-"):
        url = f"https://github.com/advisories/{primary}"
    elif primary.startswith(("EEF-", "CVE-")) and not url:
        url = f"https://osv.dev/vulnerability/{primary}"
    aliases = ", ".join(ghutil.md_text(i) for i in f["ids"][1:4])
    return ghutil.md_link(primary, url) + (f" ({aliases})" if aliases else "")


def git_dep_alerts(deps) -> list[tuple]:
    return [(d, a) for d in deps or [] for a in d.get("advisories") or [] if a.get("affects") != "no"]


def render_git_deps(deps: list[dict]) -> list[str]:
    if not deps:
        return []
    lines = [f"### Git dependencies ({len(deps)})", "",
             "Not covered by the Hex advisory tools. The pinned commit is compared with the branch it tracks "
             "(or the repository's default branch).", "",
             "| Dependency | Version | Repository | Pinned | Compared with | Commits behind | Advisories that may apply |",
             "|---|---|---|---|---|---|---|"]
    for d in deps:
        relevant = [a for a in d.get("advisories") or [] if a.get("affects") != "no"]
        ignored = len(d.get("advisories") or []) - len(relevant)
        advs = ", ".join(ghutil.md_link(a["id"], a["url"]) + f" ({ghutil.md_text(a['severity'])}"
                         + (", range not readable" if a.get("affects") == "unknown" else "") + ")"
                         for a in relevant) or ("none" if d.get("advisories") is not None else "not checked")
        if ignored:
            advs += f"; {ignored} not affecting this version"
        behind = d.get("behind_by")
        lines.append("| " + " | ".join([
            ghutil.md_code(d["name"]), ghutil.md_code(d.get("version") or "?"),
            ghutil.md_link(d["repo"], d.get("url")),
            ghutil.md_code(d["sha"][:12]), ghutil.md_text(d.get("compared_with") or "?"),
            ghutil.md_text("?" if behind is None else behind), advs,
        ]) + " |")
    lines.append("")
    return lines


def render(findings: list[dict], now: str | None = None, problems: list[str] | None = None,
           git_deps: list[dict] | None = None) -> str | None:
    problems = problems or []
    git_advisories = bool(git_dep_alerts(git_deps))
    if not findings and not problems and not git_advisories:
        return None
    now = now or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    fail = failing(findings)
    baselined = [f for f in fail if "baseline" in f]
    lines = [
        MARKER,
        f"Unresolved findings from the scheduled dependency and image scan, updated {now}.",
        "",
        "| Severity | Findings | With a fix |",
        "|---|---|---|",
    ]
    for s in SEVERITIES:
        if counts[s]:
            fixable = sum(1 for f in findings if f["severity"] == s and f["fix_available"])
            lines.append(f"| {s.upper()} | {counts[s]} | {fixable} |")
    lines += ["", f"**{len(fail) - len(baselined)}** of {len(findings)} would fail a pull request "
              "(CRITICAL or HIGH with a fix available, or a package retired for security reasons); "
              f"{len(baselined)} more are accepted in "
              "[`.github/security-baseline.yml`](../blob/main/.github/security-baseline.yml) until their review date.",
              "",
              f"{sum(1 for f in findings if f.get('build_time'))} of the findings are in build-time (npm dev) "
              "dependencies, marked `(build-time)` under Where: they do not ship in the image's runtime, but run "
              "in CI and in the image build, so the same rule applies to them.", ""]
    if problems:
        lines += ["### Baseline problems (these fail the gate)", ""] + [f"- {ghutil.md_text(p)}" for p in problems] + [""]
    for s in SEVERITIES:
        group = [f for f in findings if f["severity"] == s]
        if not group:
            continue
        lines += [f"### {s.upper()} ({len(group)})", "",
                  "| Package | Installed | Fixed in | Fix | Advisory | Summary | Where | Baseline |",
                  "|---|---|---|---|---|---|---|---|"]
        for f in group:
            fixed = ghutil.md_code(f["fixed"]) if f["fixed"] else ("see advisory" if f["fix_available"] else "none")
            title = f["title"][:120] + ("..." if len(f["title"]) > 120 else "")
            if f["kind"] == "retired":
                title = "Retired: " + title
            base = f"until {f['baseline']['review_by']}" if "baseline" in f else ""
            lines.append("| " + " | ".join([
                ghutil.md_code(f["package"]), ghutil.md_code(f["installed"]), fixed,
                "yes" if f["fix_available"] else "no", advisory_link(f),
                ghutil.md_text(title), ghutil.md_text(", ".join(f["locations"])), base,
            ]) + " |")
        lines.append("")
    lines += render_git_deps(git_deps or [])
    url = ghutil.run_url()
    if url:
        lines.append(f"Report from [this workflow run]({url}).")
    lines.append("This issue is maintained by the security workflow: it is updated in place and closed when no findings remain.")
    return ghutil.cap_body("\n".join(lines) + "\n")


# ------------------------------------------------------------------ main


def cmd_collect(a) -> int:
    findings: list[dict] = []
    if a.mix_audit:
        findings += parse_mix_audit(a.mix_audit)
    if a.hex_sarif:
        findings += parse_hex_sarif(a.hex_sarif)
    for spec in a.npm or []:
        loc, report, lock = spec.split("=", 2) if spec.count("=") == 2 else (None, None, None)
        if not loc:
            raise InputError(f"--npm expects LOCATION=REPORT=LOCKFILE, got {spec}")
        findings += parse_npm_audit(report, loc, lock)
    for spec in a.trivy or []:
        label, _, path = spec.partition("=")
        findings += parse_trivy(path, label)
    git_deps = None
    if a.git_deps:
        git_deps = _load(a.git_deps)
        if not isinstance(git_deps, dict) or not isinstance(git_deps.get("git_deps"), list):
            raise InputError(f"{a.git_deps}: not a git dependency report")
        git_deps = git_deps["git_deps"]
    enrich(findings)
    merged = merge(findings)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump({"generated": datetime.now(timezone.utc).isoformat(), "findings": merged,
                   "git_deps": git_deps}, f, indent=1)
    print(f"{len(findings)} raw findings, {len(merged)} after merging -> {a.out}")
    return 0


def load_report(path: str) -> dict:
    data = _load(path)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise InputError(f"{path}: not a findings file")
    return data


def load_findings(path: str) -> list[dict]:
    return load_report(path)["findings"]


def _evaluated(a):
    report = load_report(a.findings)
    today = date.fromisoformat(a.today) if a.today else datetime.now(timezone.utc).date()
    blocking, problems = gate_result(report["findings"], load_baseline(a.baseline), today)
    return report, blocking, problems


def cmd_gate(a) -> int:
    report, blocking, problems = _evaluated(a)
    findings = report["findings"]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    print("findings by severity: " + ", ".join(f"{s}={n}" for s, n in counts.items()))
    for f in failing(findings):
        tag = f"BASELINED until {f['baseline']['review_by']}" if "baseline" in f else "FAIL"
        print(f"{tag:22} {f['severity'].upper():8} {f['package']} {f['installed']} -> {f['fixed'] or '?'}  {f['ids'][0]}")
    for p in problems:
        print(f"BASELINE PROBLEM       {p}")
    if blocking or problems:
        print(f"\n{len(blocking)} finding(s) are CRITICAL/HIGH with a fix available (or retired for "
              f"security reasons) and not in the baseline; {len(problems)} baseline problem(s).")
        return 1
    print("gate passed")
    return 0


def cmd_render(a) -> int:
    report, _, problems = _evaluated(a)
    body = render(report["findings"], problems=problems, git_deps=report.get("git_deps"))
    repo = os.environ.get("GITHUB_REPOSITORY")
    if body and repo:
        body = body.replace("](../blob/main/", f"](https://github.com/{repo}/blob/main/")
    print(body if body is not None else "(no findings: the tracking issue would be closed)")
    return 0


def cmd_issue(a) -> int:
    report, _, problems = _evaluated(a)
    body = render(report["findings"], problems=problems, git_deps=report.get("git_deps"))
    repo = a.repo or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise InputError("--repo or GITHUB_REPOSITORY is required")
    if body:
        body = body.replace("](../blob/main/", f"](https://github.com/{repo}/blob/main/")
    existing = ghutil.find_open_issues(repo, LABEL, MARKER)
    if a.simulate_open_issue:
        if not a.dry_run:
            raise InputError("--simulate-open-issue only works with --dry-run")
        existing = [{"number": a.simulate_open_issue, "body": MARKER + "\n(simulated)"}]
    actions = ghutil.plan_issue(existing, body, "No unresolved findings remain in the latest scan. Closing.")
    if a.dry_run:
        print(f"[dry-run] open tracking issues: {[i['number'] for i in existing]}")
        print(f"[dry-run] plan: {[x[:2] if x[0] != 'create' else ('create',) for x in actions] or 'nothing to do'}")
        print("----- body -----")
        print(body if body is not None else "(none)")
    ghutil.apply_issue_actions(repo, actions, TITLE, LABEL, "b60205",
                               "Unresolved vulnerability findings", a.dry_run)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--mix-audit")
    c.add_argument("--hex-sarif")
    c.add_argument("--npm", action="append", help="LOCATION=REPORT.json=path/to/package-lock.json")
    c.add_argument("--trivy", action="append", help="LABEL=REPORT.json")
    c.add_argument("--git-deps", help="report written by git_deps.py")
    c.add_argument("--out", required=True)
    parsers = []
    for name in ("gate", "render", "issue"):
        s = sub.add_parser(name)
        s.add_argument("findings")
        s.add_argument("--baseline", default=DEFAULT_BASELINE)
        s.add_argument("--today", help="YYYY-MM-DD; for tests")
        parsers.append(s)
    i = parsers[2]
    i.add_argument("--repo")
    i.add_argument("--dry-run", action="store_true")
    i.add_argument("--simulate-open-issue", type=int, metavar="NUMBER",
                   help="dry-run only: pretend this tracking issue is open")
    a = p.parse_args(argv)
    try:
        return {"collect": cmd_collect, "gate": cmd_gate, "render": cmd_render, "issue": cmd_issue}[a.cmd](a)
    except InputError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
