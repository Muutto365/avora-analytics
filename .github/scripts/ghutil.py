"""Shared helpers for the vulnerability tracking scripts.

Standard library only, so the scripts run on a bare runner.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

GITHUB_API = "https://api.github.com"
USER_AGENT = "vulnerability-tracking-script"
BODY_LIMIT = 60000


class HttpError(Exception):
    def __init__(self, status: int, url: str, body: str = ""):
        super().__init__(f"HTTP {status} for {url}: {body[:300]}")
        self.status = status


def http(method: str, url: str, data=None, accept="application/json", retries=3):
    """Returns (status, parsed JSON or text). Raises HttpError on >= 400."""
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith(GITHUB_API):
        headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    last = None
    for attempt in range(retries):
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8", "replace")
                ctype = resp.headers.get("Content-Type", "")
                if "json" in ctype and raw:
                    return resp.status, json.loads(raw)
                return resp.status, raw
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            last = HttpError(e.code, url, text)
            if e.code < 500 and e.code != 429:
                raise last
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
        time.sleep(2 * (attempt + 1))
    raise last


def get_json(url: str):
    return http("GET", url)[1]


# ---------------------------------------------------------------- versions


def version_key(v: str):
    """Natural sort key for version strings (semver, hex, npm, distro).

    "1.18.3" > "1.18.1"; "3" == "3.0.0"; a pre-release suffix such as
    "-rc.1" sorts before the release.
    """
    v = v.strip().lstrip("vV")
    main, _, pre = v.partition("-") if re.match(r"^\d", v) else (v, "", "")
    # distro revisions like "3.5.4-r0" are not pre-releases
    if pre and re.match(r"^r\d+$", pre):
        main, pre = v, ""
    parts = [int(p) if p.isdigit() else p for p in re.split(r"[.+_~-]", main) if p]
    while len(parts) < 3:
        parts.append(0)
    while len(parts) > 3 and parts[-1] == 0:
        parts.pop()
    pre_key = (1,) if not pre else (0, tuple(
        (0, int(p), "") if p.isdigit() else (1, 0, p) for p in re.split(r"[.]", pre)))
    norm = tuple((0, p, "") if isinstance(p, int) else (1, 0, p) for p in parts)
    return (norm, pre_key)


def vcmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def is_stable_tag(tag: str) -> bool:
    return re.fullmatch(r"v?\d+(\.\d+){1,3}", tag) is not None


_COMP = re.compile(r"^\s*(>=|<=|==|=|>|<)?\s*v?([0-9][0-9A-Za-z.+\-]*)\s*$")


def in_range(version: str, expr: str):
    """Evaluates a vulnerable-version range such as ">= 3, < 3.2.1",
    ">=3 and < 3.2.1" or "< 1.0 || >= 2.0, < 2.1".

    Returns True/False, or None when the expression cannot be parsed.
    """
    if not expr or not expr.strip():
        return None
    alternatives = re.split(r"\|\||\bor\b", expr)
    any_true = False
    for alt in alternatives:
        parts = [p for p in re.split(r",|&&|\band\b", alt) if p.strip()]
        if not parts:
            return None
        ok = True
        for part in parts:
            m = _COMP.match(part)
            if not m:
                return None
            op, ver = m.group(1) or "=", m.group(2)
            c = vcmp(version, ver)
            ok = ok and {
                ">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0,
                "=": c == 0, "==": c == 0,
            }[op]
        any_true = any_true or ok
    return any_true


# ------------------------------------------------------------- markdown


def md_text(s) -> str:
    """Third-party text made safe for one table cell: no mentions, no
    pipes or newlines, no markup that could break the table."""
    s = str(s or "")
    s = re.sub(r"[\r\n]+", " ", s)
    s = s.replace("|", "\\|").replace("`", "'")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"@(?=\w)", "@​", s)
    return s.strip()


def md_code(s) -> str:
    s = str(s or "").replace("`", "'").replace("|", "\\|")
    return f"`{s}`" if s else ""


def md_link(text, url) -> str:
    url = str(url or "")
    if not re.match(r"^https://[^\s()<>]+$", url):
        return md_text(text)
    return f"[{md_text(text)}]({url})"


def cap_body(body: str, limit: int = BODY_LIMIT) -> str:
    if len(body) <= limit:
        return body
    note = "\n\n_The list was cut to fit the issue size limit; see the workflow run for the full report._\n"
    cut = body.rfind("\n", 0, limit - len(note))
    return body[: cut if cut > 0 else limit - len(note)] + note


# ---------------------------------------------------------------- issues


def plan_issue(existing: list[dict], body: str | None, close_comment: str) -> list[tuple]:
    """Decides what to do with the tracking issue.

    `existing` holds the open issues that carry the marker, oldest first.
    `body` is the new body, or None when nothing is left to report.
    Returns a list of actions:
      ("create", body) | ("update", number, body) | ("noop", number)
      | ("close", number, comment)
    Extra open copies are closed so there is only ever one.
    """
    actions: list[tuple] = []
    keep, extra = (existing[0], existing[1:]) if existing else (None, [])
    for issue in extra:
        actions.append(("close", issue["number"], f"Duplicate of #{keep['number']}."))
    if body is None:
        if keep:
            actions.append(("close", keep["number"], close_comment))
        return actions
    if keep is None:
        actions.append(("create", body))
    elif (keep.get("body") or "").strip() == body.strip():
        actions.append(("noop", keep["number"]))
    else:
        actions.append(("update", keep["number"], body))
    return actions


def find_open_issues(repo: str, label: str, marker: str) -> list[dict]:
    url = f"{GITHUB_API}/repos/{repo}/issues?state=open&labels={label}&per_page=100&sort=created&direction=asc"
    issues = get_json(url)
    return [i for i in issues if "pull_request" not in i and marker in (i.get("body") or "")]


def ensure_label(repo: str, name: str, color: str, description: str):
    try:
        get_json(f"{GITHUB_API}/repos/{repo}/labels/{name}")
    except HttpError as e:
        if e.status != 404:
            raise
        http("POST", f"{GITHUB_API}/repos/{repo}/labels",
             {"name": name, "color": color, "description": description})


def apply_issue_actions(repo: str, actions, title: str, label: str,
                        label_color: str, label_desc: str, dry_run: bool):
    for action in actions:
        kind = action[0]
        if kind == "noop":
            print(f"issue #{action[1]}: unchanged")
            continue
        if dry_run:
            if kind == "create":
                print(f"[dry-run] would create issue '{title}' with label '{label}'")
            elif kind == "update":
                print(f"[dry-run] would update issue #{action[1]}")
            elif kind == "close":
                print(f"[dry-run] would comment on and close issue #{action[1]}: {action[2]}")
            continue
        if kind == "create":
            ensure_label(repo, label, label_color, label_desc)
            _, issue = http("POST", f"{GITHUB_API}/repos/{repo}/issues",
                            {"title": title, "body": action[1], "labels": [label]})
            print(f"created issue #{issue['number']}")
        elif kind == "update":
            http("PATCH", f"{GITHUB_API}/repos/{repo}/issues/{action[1]}",
                 {"title": title, "body": action[2]})
            print(f"updated issue #{action[1]}")
        elif kind == "close":
            http("POST", f"{GITHUB_API}/repos/{repo}/issues/{action[1]}/comments",
                 {"body": action[2]})
            http("PATCH", f"{GITHUB_API}/repos/{repo}/issues/{action[1]}",
                 {"state": "closed", "state_reason": "completed"})
            print(f"closed issue #{action[1]}")


def run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run:
        return f"{server}/{repo}/actions/runs/{run}"
    return ""
