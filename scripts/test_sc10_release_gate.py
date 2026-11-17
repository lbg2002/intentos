import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    'sc10_release_gate', pathlib.Path(__file__).with_name('sc10_release_gate.py')
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateTests(unittest.TestCase):
    def make_root(self, status):
        tmp = tempfile.TemporaryDirectory()
        root = pathlib.Path(tmp.name)
        p = root / 'docs/tasks/system-control/STATUS.md'
        p.parent.mkdir(parents=True)
        p.write_text(status, encoding='utf-8')
        return tmp, root

    def test_incomplete_packages_block(self):
        tmp, root = self.make_root('| SC-05 | name | dep | implemented_unverified | - | - |\\n')
        try:
            result = gate.check(root)
            self.assertFalse(result['release_allowed'])
            self.assertEqual(result['blocked_packages'], 10)
        finally:
            tmp.cleanup()

    def test_unverifiable_evidence_is_never_a_release_pass(self):
        table = ''.join(f'| {p} | n | dep | verified | sha | note |\\n' for p in gate.PACKAGES)
        tmp, root = self.make_root(table)
        try:
            result = gate.check(root)
            self.assertFalse(result['release_allowed'])
            self.assertTrue(any(e['reason'] == 'missing_or_invalid_evidence' for e in result['blockers']))
        finally:
            tmp.cleanup()

    def test_all_evidence_layers_must_be_pass(self):
        table = ''.join(f'| {p} | n | dep | verified | sha | note |\\n' for p in gate.PACKAGES)
        tmp, root = self.make_root(table)
        try:
            folder = root / 'docs/validation/release'
            folder.mkdir(parents=True)
            for p in gate.PACKAGES:
                (folder / f'{p.lower()}.json').write_text(json.dumps({
                    'package': p, 'tested_sha': 'a' * 40,
                    'tests': [
                        {'layer': 'L1', 'result': 'pass', 'runner': 'fixture', 'command': 'true'},
                        {'layer': 'L2', 'result': 'skipped', 'runner': 'fixture', 'command': 'false'},
                    ],
                }), encoding='utf-8')
            result = gate.check(root)
            self.assertFalse(result['release_allowed'])
            self.assertTrue(any(e['reason'] == 'failed_skipped_or_incomplete_test' for e in result['blockers']))
        finally:
            tmp.cleanup()


if __name__ == '__main__':
    unittest.main()
