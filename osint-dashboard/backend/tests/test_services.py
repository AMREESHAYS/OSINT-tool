import unittest

from services.ai_summary import generate_summary
from services.email_osint import get_email_intelligence
from services.graph_builder import build_graph
from services.input_analyzer import InputAnalyzer


class ServiceTests(unittest.TestCase):
    def test_input_analyzer_classifies_email(self) -> None:
        response = InputAnalyzer.classify("analyst@gmail.com")
        self.assertEqual(response.input_type.value, "email")

    def test_email_osint_returns_empty_for_unknown_domain(self) -> None:
        payload = get_email_intelligence("user@unknown-domain.test")
        self.assertEqual(payload["breaches"], [])

    def test_graph_builder_builds_email_breach_edge(self) -> None:
        graph = build_graph(
            {
                "query": "analyst@gmail.com",
                "input_type": "email",
                "details": {
                    "email_intelligence": {
                        "breaches": [{"name": "Collection #1", "date": "2019-01-01", "data_exposed": ["email"]}]
                    }
                },
            }
        )
        self.assertGreaterEqual(len(graph["nodes"]), 2)
        self.assertGreaterEqual(len(graph["edges"]), 1)

    def test_ai_summary_mentions_breach_risk(self) -> None:
        summary = generate_summary(
            {
                "query": "analyst@gmail.com",
                "input_type": "email",
                "details": {
                    "email_intelligence": {
                        "breaches": [{"name": "Collection #1", "date": "2019-01-01", "data_exposed": ["email"]}
                        ]
                    },
                    "graph": {"nodes": [], "edges": []},
                },
            }
        )
        self.assertIn("risk", summary.lower())


if __name__ == "__main__":
    unittest.main()
