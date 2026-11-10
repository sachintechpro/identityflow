"""Regression checks for temporary per-browser training labs."""
import unittest
from app.server import get_lab, reset_lab, LABS, LAB_LOCK
from app.security import AuthError, DEMO_PASSWORD

class DemoIsolationTests(unittest.TestCase):
    def test_different_browser_labs_do_not_share_account_state(self):
        a, first, new = get_lab()
        b, second, new2 = get_lab()
        self.assertNotEqual(a, b)
        self.assertIsNot(first, second)
        token = first.request_reset('alex.viewer@example.test')['demo_token']
        first.reset_password(token, 'ChangedPass!2027')
        with self.assertRaises(AuthError):
            first.login('alex.viewer', DEMO_PASSWORD)
        self.assertEqual(second.login('alex.viewer', DEMO_PASSWORD)['role'], 'viewer')
        reset_lab(a)
        _, restored, _ = get_lab(a)
        self.assertEqual(restored.login('alex.viewer', DEMO_PASSWORD)['role'], 'viewer')
        with LAB_LOCK:
            LABS.pop(a, None)
            LABS.pop(b, None)

    def test_same_browser_retains_lab(self):
        a, first, _ = get_lab()
        same, second, is_new = get_lab(a)
        self.assertEqual(a, same)
        self.assertIs(first, second)
        self.assertFalse(is_new)
        with LAB_LOCK: LABS.pop(a, None)
