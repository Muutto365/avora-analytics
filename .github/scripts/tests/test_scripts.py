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

import ghutil  # noqa: E402
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
                  "advisories": [{"status": "no"}]}
        self.assertIsNone(uw.render(report))


if __name__ == "__main__":
    unittest.main()
