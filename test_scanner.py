import socket
import threading
import unittest
from unittest.mock import patch

from scanner import (
    parse_target,
    parse_ports,
    scan_port,
    check_web,
    make_finding,
)


class ScannerTests(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(
            parse_target("https://example.com/path"), "example.com"
        )

    def test_ip(self):
        self.assertEqual(parse_target("127.0.0.1"), "127.0.0.1")

    def test_reject_credentials(self):
        with self.assertRaises(ValueError):
            parse_target("https://user:pass@example.com")

    def test_ports(self):
        self.assertEqual(
            parse_ports("22,80,443,80-82"), [22, 80, 81, 82, 443]
        )

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("0,80")

    def test_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-20")

    def test_open_port(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            result = scan_port("127.0.0.1", port, 1)
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["port"], port)

    def test_closed_port(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            closed_port = sock.getsockname()[1]
        result = scan_port("127.0.0.1", closed_port, 1)
        self.assertNotEqual(result["state"], "open")

    def test_http_response_is_classified(self):
        import scanner
        from email.message import Message

        class FakeResponse:
            code = 200

            def __init__(self, url):
                self.url = url
                self.headers = Message()

            def geturl(self):
                return self.url

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        findings, checks = [], []
        with patch.object(
            scanner, "urlopen",
            side_effect=[
                FakeResponse("http://127.0.0.1/"),
                FakeResponse("https://127.0.0.1/"),
            ],
        ):
            check_web("127.0.0.1", 1, findings, checks)

        self.assertTrue(any(
            c.get("check") == "HTTP" and c.get("http_status") == 200
            for c in checks
        ))
        self.assertTrue(any(
            c.get("check") == "HTTPS" and c.get("http_status") == 200
            for c in checks
        ))

    def test_http_5xx_is_not_confirmed_vulnerability(self):
        import scanner
        from unittest.mock import patch

        findings, checks = [], []

        class FakeResponse:
            code = 503

            def __init__(self, url):
                from email.message import Message
                self.url = url
                self.headers = Message()

            def geturl(self):
                return self.url

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        responses = [
            FakeResponse("http://127.0.0.1/"),
            FakeResponse("https://127.0.0.1/"),
        ]

        with patch.object(scanner, "urlopen", side_effect=responses):
            check_web("127.0.0.1", 1, findings, checks)

        five_xx = [f for f in findings if f["title"] == "Resposta HTTP 5xx"]
        self.assertTrue(five_xx)
        self.assertTrue(all(f["confidence"] != "confirmed" for f in five_xx))

    def test_needs_review_is_not_confirmed(self):
        finding = make_finding(
            "LOW", "HTTP não redirecionou para HTTPS", "localhost",
            "resposta local", "validar configuração", "needs_review"
        )
        self.assertEqual(finding["confidence"], "needs_review")
        self.assertNotEqual(finding["confidence"], "confirmed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
