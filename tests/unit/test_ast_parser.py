from pathlib import Path
import unittest

from lsa.ingest.ast_parser import parse_python_file


class AstParserTests(unittest.TestCase):
    def test_extracts_functions_and_external_hosts(self) -> None:
        root = Path("tests/fixtures/sample_service").resolve()
        module = parse_python_file(root, root / "app.py")

        by_name = {function.name: function for function in module.functions}
        self.assertIn("charge_customer", by_name)
        self.assertIn("notify_customer", by_name)
        self.assertIn("api.stripe.com", by_name["charge_customer"].external_hosts)
        self.assertIn("api.mailgun.net", by_name["notify_customer"].external_hosts)


if __name__ == "__main__":
    unittest.main()
