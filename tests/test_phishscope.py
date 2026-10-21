import json
from pathlib import Path
import unittest

from phishscope.parser import parse_eml
from phishscope.report import as_json, as_markdown
from phishscope.scoring import analyze, defang

ROOT = Path(__file__).resolve().parents[1]


class PhishScopeTests(unittest.TestCase):
    def test_sample_phish_scores_malicious(self):
        result = analyze(parse_eml(ROOT / "samples/sample_phish.eml"))
        self.assertEqual(result["verdict"], "LIKELY MALICIOUS")
        self.assertGreaterEqual(result["score"], 60)

    def test_benign_sample_scores_low(self):
        result = analyze(parse_eml(ROOT / "samples/sample_benign.eml"))
        self.assertLess(result["score"], 30)

    def test_attachment_hash_is_sha256(self):
        result = parse_eml(ROOT / "samples/sample_phish.eml")
        self.assertEqual(len(result["attachments"][0]["sha256"]), 64)

    def test_attachment_not_written_to_disk(self):
        result = parse_eml(ROOT / "samples/sample_phish.eml")
        self.assertEqual(len(result["attachments"]), 1)
        self.assertFalse((ROOT / "invoice.pdf.exe").exists())

    def test_defang_changes_http_and_dots(self):
        self.assertEqual(defang("http://example.com"), "hxxp://example[.]com")

    def test_duplicate_rule_is_scored_once(self):
        email = parse_eml(ROOT / "samples/sample_phish.eml")
        email["links"] *= 3
        result = analyze(email)
        self.assertEqual(sum(item["rule"] == "ip-url" for item in result["findings"]), 1)

    def test_score_is_capped_at_100(self):
        result = analyze(parse_eml(ROOT / "samples/sample_phish.eml"))
        self.assertLessEqual(result["score"], 100)

    def test_authentication_failures_are_reported(self):
        result = analyze(parse_eml(ROOT / "samples/sample_phish.eml"))
        rules = {item["rule"] for item in result["findings"]}
        self.assertTrue({"spf-fail", "dmarc-fail"}.issubset(rules))

    def test_report_contains_defanged_indicator(self):
        result = analyze(parse_eml(ROOT / "samples/sample_phish.eml"))
        self.assertIn("hxxp://192[.]0[.]2[.]15/login", result["iocs"]["urls"])

    def test_json_report_parses(self):
        result = analyze(parse_eml(ROOT / "samples/sample_phish.eml"))
        self.assertEqual(json.loads(as_json([result]))["verdict"], result["verdict"])

    def test_markdown_report_has_findings(self):
        result = analyze(parse_eml(ROOT / "samples/sample_phish.eml"))
        self.assertIn("## Findings", as_markdown(result))


if __name__ == "__main__":
    unittest.main()
