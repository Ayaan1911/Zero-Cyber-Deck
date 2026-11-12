import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scope_guard import approved


class ScopeGuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'scope.txt'
        self.path.write_text('192.168.56.0/24\n10.0.0.2\nlab.example\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_allowed_host(self):
        self.assertTrue(approved(self.path, '192.168.56.42', 'host'))
        self.assertTrue(approved(self.path, 'lab.example', 'host'))

    def test_not_allowed_host(self):
        self.assertFalse(approved(self.path, '192.168.1.1', 'host'))
        self.assertFalse(approved(self.path, 'notlab.example', 'host'))
        self.assertFalse(approved(self.path, 'evil.lab.example', 'host'))

    def test_network(self):
        self.assertTrue(approved(self.path, '192.168.56.0/24', 'network'))
        with self.assertRaises(ValueError):
            approved(self.path, '192.168.0.0/16', 'network')
        self.assertFalse(approved(self.path, '192.168.55.0/24', 'network'))

    def test_urls(self):
        self.assertTrue(approved(self.path, 'https://lab.example:8443/health?q=x', 'url'))
        self.assertFalse(approved(self.path, 'https://google.com', 'url'))
        with self.assertRaises(ValueError):
            approved(self.path, 'https://user:pass@lab.example', 'url')
        with self.assertRaises(ValueError):
            approved(self.path, 'file:///etc/passwd', 'url')

    def test_invalid(self):
        with self.assertRaises(ValueError):
            approved(self.path, '-p80', 'host')
        with self.assertRaises(ValueError):
            approved(self.path, '2001:db8::1', 'host')

    def test_empty(self):
        self.path.write_text('# Empty\n')
        with self.assertRaises(ValueError):
            approved(self.path, '192.168.56.1', 'host')


if __name__ == '__main__':
    unittest.main()
