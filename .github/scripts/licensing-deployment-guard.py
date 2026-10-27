"""Skip automatic publication only for the reviewed licensing snapshot.

The exemption matches only this snapshot directly above BASE; normal runtime
changes and explicit workflow_dispatch retain their publication behavior.
shortcut: this exemption is snapshot-bound; refresh BASE/hashes if rebased.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

BASE = 'dc094224b8359efeda30c5c0c15a618fd8982967'
EXPECTED = {
    ".github/workflows/deploy-yc.yml": "6eeb53ad3ba39bfd09b38b080ed79a42c5b7a090bdb89aaaa82356d1036faf7a",
    ".github/workflows/publish.yml": "54917252241e4459171f0c1d8c5fab7dc7ccda1fccfe02c2fb5a05e46a47ffbd",
    "LICENSE": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
    "README.md": "40062e2228495d0d9842cad33e039e0bb1dee5ff8e38a0abc6ba409a0905d462"
}
SCRIPT = '.github/scripts/licensing-deployment-guard.py'


def licensing_only(parent, files):
    return parent == BASE and files == EXPECTED


def self_test():
    assert licensing_only(BASE, dict(EXPECTED))
    assert not licensing_only('another-parent', dict(EXPECTED))
    assert not licensing_only(BASE, {**EXPECTED, 'runtime.py': 'changed'})
    assert not licensing_only(BASE, {**EXPECTED, 'package.json': 'changed'})
    assert not licensing_only(BASE, {})
    print('licensing deployment guard: 5 checks passed')


def should_deploy():
    event = os.environ.get('GITHUB_EVENT_NAME')
    if event not in ('push', 'workflow_run', 'pull_request') or os.environ.get('GITHUB_REF_TYPE') == 'tag':
        return True
    parent = subprocess.check_output(['git', 'rev-parse', 'HEAD^'], text=True).strip()
    if parent != BASE:
        return True
    paths = subprocess.check_output(
        ['git', 'diff', '--name-only', '-z', BASE, 'HEAD']
    ).decode().split('\0')[:-1]
    if SCRIPT not in paths:
        return True
    files = {
        path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
        for path in paths if path != SCRIPT
    }
    return not licensing_only(parent, files)


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        deploy = should_deploy()
        print('deploy=' + str(deploy).lower())
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write('deploy=' + str(deploy).lower() + '\n')
