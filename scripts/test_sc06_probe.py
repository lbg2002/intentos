import importlib.util
import pathlib
import tempfile
import unittest

MODULE = pathlib.Path(__file__).with_name('sc06_certification_probe.py')
spec = importlib.util.spec_from_file_location('sc06_probe', MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class TestSc06Probe(unittest.TestCase):
    def test_all_classes_and_actions_unverified(self):
        evidence = probe.collect([], '')
        self.assertEqual(len(evidence['actions']), 35)
        self.assertEqual(evidence['summary']['passed'], 0)
        self.assertTrue(all(x['certification_state'] == 'unverified' for x in evidence['actions']))

    def test_discovery_is_not_certification(self):
        with tempfile.TemporaryDirectory() as root:
            p = pathlib.Path(root)
            (p / 'firefox.desktop').write_text('[Desktop Entry]\\nName=Firefox\\n', encoding='utf-8')
            rows = probe.inventory([p], 'wayland')
            browser = next(x for x in rows if x['target_class'] == 'browser')
            self.assertEqual(browser['discovery_state'], 'desktop_entry_observed')
            self.assertEqual(browser['test_result'], 'blocked')
            self.assertIsNone(browser['observed_version'])
            self.assertEqual(browser['certification_state'], 'unverified')

    def test_symlink_is_not_observed_installation(self):
        with tempfile.TemporaryDirectory() as root:
            p = pathlib.Path(root)
            outside = p / 'other'
            outside.write_text('stub', encoding='utf-8')
            (p / 'code.desktop').symlink_to(outside)
            ide = next(x for x in probe.inventory([p], 'x11') if x['target_class'] == 'vscode')
            self.assertEqual(ide['discovery_state'], 'unknown')

if __name__ == '__main__':
    unittest.main()
