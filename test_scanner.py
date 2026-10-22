import unittest
from scanner import parse_target, parse_ports

class ScannerTests(unittest.TestCase):
    def test_domain(self):
        self.assertEqual(parse_target("https://example.com/path"), "example.com")
    def test_ip(self):
        self.assertEqual(parse_target("127.0.0.1"), "127.0.0.1")
    def test_reject_credentials(self):
        with self.assertRaises(ValueError):
            parse_target("https://user:pass@example.com")
    def test_ports(self):
        self.assertEqual(parse_ports("22,80,443,80-82"), [22,80,81,82,443])
    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("0,80")
    def test_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("100-20")

if __name__ == "__main__":
    unittest.main()
