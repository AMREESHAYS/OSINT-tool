import unittest

from models.schemas import AnalyzeRequest
from routes.analyze import analyze_input, store


class RouteTests(unittest.TestCase):
    def test_analyze_email_stores_summary_and_graph(self) -> None:
        response = analyze_input(AnalyzeRequest(query="target@yahoo.com"))
        result = store.get(response.request_id)

        self.assertIsNotNone(result)
        details = result.details or {}
        self.assertIn("email_intelligence", details)
        self.assertIn("graph", details)
        self.assertIn("summary", details)


if __name__ == "__main__":
    unittest.main()
