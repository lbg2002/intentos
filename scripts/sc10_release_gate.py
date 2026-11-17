#!/usr/bin/env python3
"""Fail-closed SC-10 release evidence gate. Never count skipped tests as passing."""
from __future__ import annotations
import argparse
import json
import pathlib
import re

PACKAGES = tuple(f'SC-{i:02d}' for i in range(1, 11))
VALID_LAYERS = {'L1', 'L2', 'L3', 'L4'}

# Every scenario in ACCEPTANCE.md must be represented by positive evidence.
# This is a completeness check only; maintainers must inspect source logs.
REQUIRED_CASES = {
    'SC-02': {'V16'},
    'SC-03': {'V01', 'V02', 'V03', 'V04', 'V05', 'V15'},
    'SC-04': {'V06', 'V07'},
    'SC-05': {'V08'},
    'SC-06': {'V08', 'V09', 'V10'},
    'SC-07': {'V11', 'V12'},
    'SC-08': {'V13'},
    'SC-09': {'V14', 'V15'},
    'SC-10': {'V17'},
}
REQUIRED_LAYERS = {
    'SC-01': {'L1', 'L2'},
    'SC-02': {'L1', 'L4'},
    'SC-03': {'L1', 'L2'},
    'SC-04': {'L1', 'L2'},
    'SC-05': {'L1', 'L3'},
    'SC-06': {'L1', 'L3'},
    'SC-07': {'L1', 'L2', 'L3'},
    'SC-08': {'L1', 'L2'},
    'SC-09': {'L1', 'L3'},
    'SC-10': {'L1', 'L2', 'L3', 'L4'},
}


def statuses(raw: str) -> dict[str, str]:
    out = {}
    for line in raw.splitlines():
        if not line.startswith('| SC-'):
            continue
        cells = [x.strip() for x in line.strip().strip('|').split('|')]
        if len(cells) >= 4:
            out[cells[0]] = cells[3]
    return out


def check(root: pathlib.Path) -> dict:
    path = root / 'docs/tasks/system-control/STATUS.md'
    try:
        states = statuses(path.read_text(encoding='utf-8'))
    except OSError:
        states = {}
    blockers = []
    for package in PACKAGES:
        state = states.get(package, 'missing')
        if state != 'verified':
            blockers.append({'package': package, 'reason': 'not_verified', 'state': state})
            continue
        evidence = root / f'docs/validation/release/{package.lower()}.json'
        try:
            body = json.loads(evidence.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            blockers.append({'package': package, 'reason': 'missing_or_invalid_evidence'})
            continue
        if not (isinstance(body, dict)
                and body.get('package') == package
                and re.fullmatch('[0-9a-f]{40}', str(body.get('tested_sha', '')))
                and isinstance(body.get('tests'), list)
                and body['tests']):
            blockers.append({'package': package, 'reason': 'malformed_evidence'})
            continue
        entries = body['tests']
        for test in entries:
            if not (isinstance(test, dict)
                    and test.get('layer') in VALID_LAYERS
                    and test.get('result') == 'pass'
                    and isinstance(test.get('command'), str) and test['command']
                    and isinstance(test.get('runner'), str) and test['runner']):
                blockers.append({'package': package, 'reason': 'failed_skipped_or_incomplete_test'})
                break
        observed = {x.get('layer') for x in entries
                    if isinstance(x, dict) and x.get('result') == 'pass'}
        for layer in sorted(REQUIRED_LAYERS[package] - observed):
            blockers.append({'package': package, 'reason': 'missing_required_layer', 'layer': layer})
        observed_cases = {x.get('acceptance_id') for x in entries
                          if isinstance(x, dict) and x.get('result') == 'pass'}
        for case in sorted(REQUIRED_CASES.get(package, set()) - observed_cases):
            blockers.append({'package': package, 'reason': 'missing_required_case', 'case': case})
    return {
        'release_allowed': not blockers,
        'required_packages': len(PACKAGES),
        'blocked_packages': len({x['package'] for x in blockers}),
        'blockers': blockers,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parent.parent)
    args = parser.parse_args(argv)
    result = check(args.root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['release_allowed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
