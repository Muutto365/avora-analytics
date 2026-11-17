"""Offline tests for the vulnerability tracking scripts.

Run: python3 -m unittest discover -s .github/scripts/tests -v
"""

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from datetime import date  # noqa: E402

import ghutil  # noqa: E402
import git_deps as gd  # noqa: E402
import security_report as sr  # noqa: E402
import upstream_watch as uw  # noqa: E402

HEX_SARIF = {
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "hex.audit", "rules": [
            {"id": "EEF-CVE-2026-0001", "properties": {"security-severity": "9.3"}},
            {"id": "EEF-CVE-2026-0002", "properties": {"security-severity": "5.0"}},
            {"id": "RETIRED-old_pkg", "helpUri": "https://hex.pm/packages/old_pkg"},
        ]}},
        "results": [
            {"ruleId": "EEF-CVE-2026-0001",
             "partialFingerprints": {"hexAudit/v1": "advisory:hexpm/plug:EEF-CVE-2026-0001"},
             "message": {"text": "x", "arguments": [
                 "plug", "1.18.1", "EEF-CVE-2026-0001 (aka CVE-2026-0001, GHSA-aaaa-bbbb-cccc)",
                 "Plug denial of service", "https://osv.dev/vulnerability/EEF-CVE-2026-0001"]}},
            {"ruleId": "EEF-CVE-2026-0002",
             "partialFingerprints": {"hexAudit/v1": "advisory:hexpm/cloak:EEF-CVE-2026-0002"},
             "message": {"text": "x", "arguments": [
                 "cloak", "1.1.4", "EEF-CVE-2026-0002", "No fix yet",
                 "https://osv.dev/vulnerability/EEF-CVE-2026-0002"]}},
            {"ruleId": "RETIRED-old_pkg",
             "partialFingerprints": {"hexAudit/v1": "retirement:hexpm/old_pkg"},
             "message": {"text": "Dependency 'old_pkg' '0.1.0' is retired (security): use new_pkg",
                         "arguments": ["old_pkg", "0.1.0"]}},
        ],
    }],
}

MIX_AUDIT = {"pass": False, "vulnerabilities": [{
    "dependency": {"package": "plug", "version": "1.18.1", "lockfile": "mix.lock"},
    "advisory": {"id": "GHSA-aaaa-bbbb-cccc", "severity": "high", "title": "Plug denial of service",
                 "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                 "first_patched_versions": ["1.19.3", "1.18.3", "1.17.2"]},
}]}

OSV = {
    "EEF-CVE-2026-0001": {"aliases": ["CVE-2026-0001"], "affected": [{
        "package": {"name": "plug", "ecosystem": "Hex"},
        "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.18.0"}, {"fixed": "1.18.3"}, {"introduced": "1.19.0"}, {"fixed": "1.19.3"}]}]}]},
    "EEF-CVE-2026-0002": {"aliases": [], "affected": [{
        "package": {"name": "cloak", "ecosystem": "Hex"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
}


def write(tmp, name, data):
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        f.write(data if isinstance(data, str) else json.dumps(data))
    return path


class FailClosed(unittest.TestCase):
    def test_missing_empty_and_malformed_inputs_are_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(sr.InputError):
                sr.parse_mix_audit(os.path.join(tmp, "absent.json"))
            with self.assertRaises(sr.InputError):
                sr.parse_hex_sarif(write(tmp, "empty.sarif", ""))
            with self.assertRaises(sr.InputError):
                sr.parse_hex_sarif(write(tmp, "bad.sarif", {"runs": []}))
            with self.assertRaises(sr.InputError):
                sr.parse_npm_audit(write(tmp, "npm.json", {"error": {"code": "ENOLOCK"}}), "x", "x")
            with self.assertRaises(sr.InputError):
                sr.parse_trivy(write(tmp, "t.json", {"Results": []}), "image")

    def test_collect_with_a_broken_input_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "findings.json")
            code = sr.main(["collect", "--hex-sarif", write(tmp, "h.sarif", "not json"), "--out", out])
            self.assertEqual(code, 2)
            self.assertFalse(os.path.exists(out))
            # and nothing downstream can mistake the missing file for "clean"
            self.assertEqual(sr.main(["render", out]), 2)


class Collect(unittest.TestCase):
    def collect(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = sr.parse_hex_sarif(write(tmp, "h.sarif", HEX_SARIF)) \
                + sr.parse_mix_audit(write(tmp, "m.json", MIX_AUDIT))
        sr.enrich(raw, osv=lambda i: OSV[i], ghsa=lambda i: {})
        return sr.merge(raw)

    def test_aliases_merge_and_fixed_version_prefers_same_line(self):
        findings = self.collect()
        plug = [f for f in findings if f["package"] == "plug"]
        self.assertEqual(len(plug), 1)
        self.assertEqual(sorted(plug[0]["sources"]), ["hex.audit", "mix_audit"])
        self.assertEqual(plug[0]["fixed"], "1.18.3")
        self.assertEqual(plug[0]["severity"], "critical")
        self.assertEqual(plug[0]["ids"][0], "GHSA-aaaa-bbbb-cccc")

    def test_gate_rule(self):
        findings = self.collect()
        failing = {(f["package"], f["kind"]) for f in sr.failing(findings)}
        # critical with fix fails; medium without fix does not; security retirement fails
        self.assertEqual(failing, {("plug", "advisory"), ("old_pkg", "retired")})
        cloak = next(f for f in findings if f["package"] == "cloak")
        self.assertFalse(cloak["fix_available"])

    def test_render_lists_each_field(self):
        body = sr.render(self.collect(), now="T")
        self.assertIn(sr.MARKER, body)
        self.assertIn("| `plug` | `1.18.1` | `1.18.3` | yes | [GHSA-aaaa-bbbb-cccc](https://github.com/advisories/GHSA-aaaa-bbbb-cccc)", body)
        self.assertIn("| `cloak` | `1.1.4` | none | no |", body)

    def test_npm_ranges(self):
        self.assertEqual(sr.npm_range(">=4.0.0 <4.0.4"), ">=4.0.0, <4.0.4")
        self.assertEqual(sr.npm_range("6.0.0 - 7.17.0"), ">=6.0.0, <=7.17.0")
        self.assertTrue(ghutil.in_range("4.0.3", sr.npm_range(">=4.0.0 <4.0.4")))
        self.assertFalse(ghutil.in_range("2.3.1", sr.npm_range(">=4.0.0 <4.0.4")))
        self.assertTrue(ghutil.in_range("1.0", sr.npm_range("<1.2.0 || >=2.0.0 <2.1.0")))


class NpmBuildTime(unittest.TestCase):
    def test_dev_only_copies_are_marked_build_time_and_still_gate(self):
        lock = {"packages": {
            "": {}, "node_modules/foo": {"version": "1.0.0", "dev": True},
            "node_modules/bar": {"version": "2.0.0"},
            "node_modules/x/node_modules/bar": {"version": "2.0.0", "dev": True},
        }}
        audit = {"auditReportVersion": 2, "vulnerabilities": {
            "foo": {"nodes": ["node_modules/foo"], "fixAvailable": True, "via": [
                {"name": "foo", "url": "https://github.com/advisories/GHSA-1111-2222-3333",
                 "severity": "high", "range": "<1.0.1", "title": "foo bug", "source": 1}]},
            "bar": {"nodes": ["node_modules/bar", "node_modules/x/node_modules/bar"], "fixAvailable": True,
                    "via": [{"name": "bar", "url": "https://github.com/advisories/GHSA-4444-5555-6666",
                             "severity": "moderate", "range": "<2.0.1", "title": "bar bug", "source": 2}]},
        }}
        with tempfile.TemporaryDirectory() as tmp:
            raw = sr.parse_npm_audit(write(tmp, "a.json", audit), "assets/package-lock.json",
                                     write(tmp, "lock.json", lock))
        by = {f["package"]: f for f in raw}
        self.assertTrue(by["foo"]["build_time"])
        self.assertEqual(by["foo"]["locations"], ["assets/package-lock.json (build-time)"])
        self.assertFalse(by["bar"]["build_time"])  # one copy ships at runtime
        sr.enrich(raw, osv=lambda i: {}, ghsa=lambda i: {"vulnerabilities": [
            {"package": {"name": "foo"}, "first_patched_version": "1.0.1", "vulnerable_version_range": "<1.0.1"}]})
        merged = sr.merge(raw)
        self.assertEqual([f["package"] for f in sr.failing(merged)], ["foo"])
        self.assertIn("1 of the findings are in build-time", sr.render(merged, now="T"))


class Issue(unittest.TestCase):
    def test_empty_findings_close_the_open_issue(self):
        self.assertIsNone(sr.render([]))
        actions = ghutil.plan_issue([{"number": 7, "body": sr.MARKER}], None, "clean")
        self.assertEqual(actions, [("close", 7, "clean")])

    def test_empty_findings_without_issue_do_nothing(self):
        self.assertEqual(ghutil.plan_issue([], None, "clean"), [])

    def test_create_update_noop_and_deduplicate(self):
        self.assertEqual(ghutil.plan_issue([], "B", "c"), [("create", "B")])
        self.assertEqual(ghutil.plan_issue([{"number": 1, "body": "B"}], "B", "c"), [("noop", 1)])
        self.assertEqual(ghutil.plan_issue([{"number": 1, "body": "A"}, {"number": 2, "body": "A"}], "B", "c"),
                         [("close", 2, "Duplicate of #1."), ("update", 1, "B")])

    def test_third_party_text_is_neutralised(self):
        s = ghutil.md_text("hi @someone | x\n<script>`")
        self.assertNotIn("@someone", s)
        self.assertNotIn("\n", s)
        self.assertNotIn("<script>", s)
        self.assertIn("\\|", s)

    def test_body_is_capped(self):
        body = ghutil.cap_body("line\n" * 20000, limit=1000)
        self.assertLessEqual(len(body), 1000)
        self.assertIn("cut to fit", body)


TODAY = date(2026, 11, 17)


def entry(i, pkg, review_by="2026-12-01", reason="tracked in #1"):
    return {"id": i, "package": pkg, "reason": reason, "review_by": review_by}


class Baseline(Collect):
    def test_baselined_finding_passes_and_is_marked(self):
        findings = self.collect()
        # baseline by an alias (CVE) rather than the displayed GHSA id
        blocking, problems = sr.gate_result(findings, [entry("CVE-2026-0001", "plug")], TODAY)
        self.assertEqual([f["package"] for f in blocking], ["old_pkg"])
        self.assertEqual(problems, [])
        plug = next(f for f in findings if f["package"] == "plug")
        self.assertEqual(plug["baseline"]["review_by"], "2026-12-01")
        self.assertIn("| until 2026-12-01 |", sr.render(findings, now="T"))

    def test_expired_far_stale_and_incomplete_entries_fail(self):
        findings = self.collect()
        entries = [
            entry("CVE-2026-0001", "plug", review_by="2026-11-16"),     # expired
            entry("EEF-CVE-2026-0002", "cloak", review_by="2027-01-30"),  # too far out
            entry("GHSA-zzzz-zzzz-zzzz", "plug"),                       # matches nothing
            {"id": "RETIRED-old_pkg", "package": "old_pkg", "review_by": "2026-12-01"},  # no reason
        ]
        blocking, problems = sr.gate_result(findings, entries, TODAY)
        self.assertEqual(len(problems), 4, problems)
        self.assertTrue(any("has passed" in p for p in problems))
        self.assertTrue(any("more than 30 days" in p for p in problems))
        self.assertTrue(any("matches no current finding" in p for p in problems))
        self.assertTrue(any("missing reason" in p for p in problems))
        # an entry with problems still marks its finding, but the gate fails
        self.assertEqual([f["package"] for f in blocking], ["old_pkg"])

    def test_same_id_on_another_package_does_not_match(self):
        findings = self.collect()
        _, problems = sr.gate_result(findings, [entry("CVE-2026-0001", "cowboy")], TODAY)
        self.assertEqual(len(problems), 1)

    def test_gate_cli_with_baseline_file(self):
        findings = self.collect()
        with tempfile.TemporaryDirectory() as tmp:
            fpath = write(tmp, "f.json", {"findings": findings})
            ok = write(tmp, "ok.yml", "entries:\n  - id: CVE-2026-0001\n    package: plug\n"
                       "    reason: \"x\"\n    review_by: 2026-12-01\n"
                       "  - id: RETIRED-old_pkg\n    package: old_pkg\n    reason: x\n    review_by: 2026-12-01\n")
            self.assertEqual(sr.main(["gate", fpath, "--baseline", ok, "--today", "2026-11-17"]), 0)
            self.assertEqual(sr.main(["gate", fpath, "--baseline", ok, "--today", "2026-12-02"]), 1)
            bad = write(tmp, "bad.yml", "entries:\n  - id: [oops]\n   package: plug\n")
            self.assertEqual(sr.main(["gate", fpath, "--baseline", bad]), 2)
            self.assertEqual(sr.main(["gate", fpath, "--baseline", os.path.join(tmp, "absent.yml")]), 2)

    def test_parser_is_strict(self):
        self.assertEqual(ghutil.parse_entry_list("entries: []\n"), [])
        for bad in ("", "other:\n", "entries:\n- id: x\n", "entries:\n  - id: a\n    id: b\n",
                    "entries: []\n  - id: a\n"):
            with self.assertRaises(ValueError, msg=bad):
                ghutil.parse_entry_list(bad)

    def test_repository_baseline_file_parses(self):
        entries = sr.load_baseline(sr.DEFAULT_BASELINE)
        for e in entries:
            self.assertEqual(set(e), {"id", "package", "reason", "review_by"})
            date.fromisoformat(e["review_by"])


class GitDeps(unittest.TestCase):
    LOCK = ('%{\n  "con_cache": {:git, "https://github.com/a/con_cache", "d050e13", [branch: "x"]},\n'
            '  "zx": {:git, "https://github.com/b/zx.git", "5c96845", []},\n'
            '  "plug": {:hex, :plug, "1.20.3", "x"},\n}\n')

    def test_parse(self):
        deps = gd.parse_git_deps(self.LOCK)
        self.assertEqual([(d["name"], d["branch"]) for d in deps], [("con_cache", "x"), ("zx", None)])
        self.assertEqual(gd.github_slug(deps[1]["url"]), "b/zx")

    def test_render_and_issue_stays_open_for_applicable_advisory(self):
        dep = {"name": "lv", "version": "1.1.18", "repo": "o/lv", "url": "https://github.com/o/lv",
               "sha": "2c59a7da2f25aaaa", "compared_with": "main (tracked branch)", "behind_by": 0,
               "advisories": [{"id": "GHSA-36m4-rm57-3prf", "url": "https://github.com/advisories/GHSA-36m4-rm57-3prf",
                               "severity": "low", "affects": "yes"},
                              {"id": "GHSA-old", "url": "", "severity": "high", "affects": "no"}]}
        body = sr.render([], git_deps=[dep], now="T")
        self.assertIn("GHSA-36m4-rm57-3prf", body)
        self.assertIn("1 not affecting this version", body)
        dep["advisories"] = dep["advisories"][1:]
        self.assertIsNone(sr.render([], git_deps=[dep]))


class Alpine(unittest.TestCase):
    def test_reports_newer_patch_and_builder(self):
        releases = {"release_branches": [{"rel_branch": "v3.22", "eol_date": "2027-05-01", "releases": [
            {"version": "3.22.8"}, {"version": "3.22.2"}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            df = write(tmp, "Dockerfile", "ARG ALPINE_VERSION=3.22.2\n"
                       "FROM hexpm/elixir:1.19.4-erlang-27.3.4.6-alpine-${ALPINE_VERSION} AS b\n")
            res = uw.alpine_status(df, releases, tag_exists=lambda t: False)
        self.assertEqual((res["pinned"], res["latest"]), ("3.22.2", "3.22.8"))
        self.assertEqual(res["builder"], "hexpm/elixir:1.19.4-erlang-27.3.4.6-alpine-3.22.8")
        report = {"slug": "u/s", "pin": "v1", "commit": "abc", "repo": "o/r", "releases": [],
                  "advisories": [], "alpine": res}
        self.assertIn("is not published yet", uw.render(report))
        res["latest"] = res["pinned"]
        self.assertIsNone(uw.render(report))


class Upstream(unittest.TestCase):
    def test_ranges(self):
        self.assertFalse(ghutil.in_range("3.2.1", ">=3 and < 3.2.1"))
        self.assertTrue(ghutil.in_range("3.1.0", ">=3 and < 3.2.1"))
        self.assertTrue(ghutil.in_range("3.2.1", "<= 3.2.1"))
        self.assertIsNone(ghutil.in_range("3.2.1", "all versions before the fix"))
        self.assertEqual(uw.advisory_status({"vulnerabilities": [{"vulnerable_version_range": "?"}]}, "3.2.1"), "unknown")

    def test_stable_tags_and_ordering(self):
        self.assertTrue(ghutil.is_stable_tag("v3.2.1"))
        self.assertFalse(ghutil.is_stable_tag("v3.2.0-rc.0"))
        self.assertGreater(ghutil.vcmp("v3.10.0", "v3.9.9"), 0)
        self.assertLess(ghutil.vcmp("3.2.0-rc.0", "3.2.0"), 0)

    def test_lock_diff_reports_packages_with_advisories(self):
        theirs_mix = '%{\n  "plug": {:hex, :plug, "1.18.3", "x"},\n  "jason": {:hex, :jason, "1.4.4", "x"},\n}\n'

        def fetch(path):
            if path == "mix.lock":
                return theirs_mix
            raise ghutil.HttpError(404, path)

        def osv(queries):
            return [["GHSA-aaaa-bbbb-cccc"] if (name, ver) == ("plug", "1.18.1") else [] for _, name, ver in queries]

        real_root = uw.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            write(tmp, "mix.lock", '%{\n  "plug": {:hex, :plug, "1.18.1", "x"},\n  "jason": {:hex, :jason, "1.4.4", "x"},\n}\n')
            uw.ROOT = tmp
            try:
                res = uw.advisory_changes("v9.9.9", "up/stream", fetch=fetch, osv=osv)
            finally:
                uw.ROOT = real_root
        self.assertEqual(res["changed"], 1)
        self.assertEqual(res["rows"], [{"file": "mix.lock", "package": "plug", "ours": ["1.18.1"],
                                        "theirs": ["1.18.3"], "advisories": ["GHSA-aaaa-bbbb-cccc"],
                                        "resolved": ["GHSA-aaaa-bbbb-cccc"]}])

    def test_nothing_new_renders_nothing(self):
        report = {"slug": "up/stream", "pin": "v1.0.0", "commit": "abc", "repo": "o/r", "releases": [],
                  "advisories": [{"status": "no"}], "alpine": None}
        self.assertIsNone(uw.render(report))


if __name__ == "__main__":
    unittest.main()
