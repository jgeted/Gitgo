"""Readback-source proof on owned trees; stdlib only, never production policy."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

_source = Path(__file__).with_name('acl-exact-matrix.py')
_spec = importlib.util.spec_from_file_location('gitgo_acl_exact_matrix', _source)
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


class Api(m.Api):
    def __init__(self):
        super().__init__()
        self.kernel_query = m.b.fn(self.a, 'GetKernelObjectSecurity',
            [W.HANDLE, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)], W.BOOL)

    def kernel_snapshot(self, handle):
        needed = W.DWORD()
        assert not self.kernel_query(handle, 0x1ff, None, 0, C.byref(needed))
        assert C.get_last_error() == 122
        assert 20 <= needed.value <= 1024 * 1024
        buffer = C.create_string_buffer(needed.value)
        self.check(self.kernel_query(handle, 0x1ff, buffer, len(buffer), C.byref(needed)))
        raw = buffer.raw[:needed.value]
        control, revision = W.WORD(), W.DWORD()
        self.check(self.control(buffer, C.byref(control), C.byref(revision)))
        return {'raw': raw, 'control': control.value}


def key(record):
    components = m.binary_components(record)
    # Preserve every ACE, ACL revision, control bit and owner/group. Only the
    # empty/absent/NULL SACL representation has no audit or MIC entry to retain.
    if components['sacl'] is None or not components['sacl']['aces']:
        components['sacl'] = None
        components['control'] &= ~0x10
    return components


def summary(record):
    def flags(offset):
        return [{'type': bytes.fromhex(ace)[0], 'flags': bytes.fromhex(ace)[1]}
                for ace in (m.b.acl_aces(record['raw'], offset) or [])]
    return {'sha256': hashlib.sha256(record['raw']).hexdigest(),
            'control': record['control'], 'dacl_ace_flags': flags(16), 'sacl_ace_flags': flags(12)}


def ordered_query_proof(api, root):
    observations = []
    for index, path in enumerate([root, *sorted(root.rglob('*'))]):
        handle = api.handle(path)
        try:
            before = api.native_snapshot(handle)
            reconstructed = api.snapshot(handle, 0x1ff)
            kernel = api.kernel_snapshot(handle)
            after = api.native_snapshot(handle)
        finally:
            api.close(handle)
        native_stable = before['raw'] == after['raw']
        kernel_equal = m.binary_components(before) == m.binary_components(kernel)
        observations.append({'object_index': index, 'native_read_stable': native_stable,
            'kernel_components_equal': kernel_equal,
            'win32_components_equal': m.binary_components(before) == m.binary_components(reconstructed),
            'native_before': summary(before), 'win32': summary(reconstructed),
            'kernel': summary(kernel), 'native_after': summary(after)})
        assert native_stable and kernel_equal
    return observations


def native_tree(api, root):
    records = {}
    for path in [root, *sorted(root.rglob('*'))]:
        handle = api.handle(path)
        try:
            records[str(path.relative_to(root))] = api.native_snapshot(handle)
        finally:
            api.close(handle)
    return records


def compare(api, left, right):
    a, z = native_tree(api, left), native_tree(api, right)
    inventory_equal = a.keys() == z.keys()
    different, representations = [], []
    for index, path in enumerate(sorted(a.keys() & z.keys())):
        if key(a[path]) != key(z[path]):
            different.append({'object_index': index, 'baseline': summary(a[path]), 'restored': summary(z[path])})
        elif m.binary_components(a[path]) != m.binary_components(z[path]):
            representations.append(index)
    return {'matched': inventory_equal and not different, 'object_count': len(a),
            'inventory_equal': inventory_equal, 'differences': different,
            'empty_sacl_representation_only': representations}


def run_case(api, editor, scenario, source):
    result = {'scenario': scenario, 'snapshot_source': source, 'phase': 'create', 'checks': []}
    handles = []
    with tempfile.TemporaryDirectory(prefix='gitgo_acl_query_proof_') as temporary:
        owned = Path(temporary).resolve()
        roots = []
        for name in ('baseline', 'restored'):
            outer = owned / name
            outer.mkdir()
            root = outer / 'workspace'
            root.mkdir()
            (root / 'nested').mkdir()
            (root / 'nested' / 'file').write_text('owned diagnostic', encoding='utf-8')
            roots.append(root)
        left, right = roots
        def edit(path, *arguments):
            assert path.resolve().is_relative_to(owned)
            subprocess.run([editor, str(path), *arguments], check=True, capture_output=True, timeout=20)
        def check(stage):
            result['checks'].append({'stage': stage, **compare(api, left.parent, right.parent)})
        try:
            result['phase'] = 'initialise'
            for root in roots:
                m.b.initialise_sacl(api, root, scenario)
            check('initial')
            assert result['checks'][-1]['matched']
            if source == 'native':
                result['query_order'] = ordered_query_proof(api, right)
            paths = [right, *sorted(right.rglob('*'))]
            for path in paths:
                handles.append(api.handle(path))
            selected = {'native': api.native_snapshot, 'kernel': api.kernel_snapshot,
                        'win32': lambda handle: api.snapshot(handle, 0x1ff)}[source]
            originals = [selected(handle) for handle in handles]
            native_originals = [api.native_snapshot(handle) for handle in handles]
            result['phase'] = 'mutate'
            for path, handle, original in zip(paths, handles, native_originals):
                api.restore(handle, api.fixture_post_descriptor(original, path.is_dir()), 'backupwrite')
            result['phase'] = 'restore'
            for handle, original in zip(handles, originals):
                api.restore(handle, original['raw'], 'backupwrite')
            for handle in reversed(handles):
                api.close(handle)
            handles.clear()
            check('restored')
            result['phase'] = 'parent-add'
            for root in roots:
                edit(root.parent, '/grant', '*S-1-5-7:(OI)(CI)R')
            check('parent-add')
            result['phase'] = 'parent-medium'
            for root in roots:
                edit(root.parent, '/setintegritylevel', '(OI)(CI)M')
            check('parent-medium')
            result['phase'] = 'new-children'
            for root in roots:
                (root / 'new-directory').mkdir()
                (root / 'new-directory' / 'new-file').write_text('future object', encoding='utf-8')
                (root / 'nested' / 'new-file').write_text('future nested object', encoding='utf-8')
            check('new-children')
            result['phase'] = 'parent-remove'
            for root in roots:
                edit(root.parent, '/remove:g', '*S-1-5-7')
            check('parent-remove')
            result['phase'] = 'parent-low'
            for root in roots:
                edit(root.parent, '/setintegritylevel', '(OI)(CI)L')
            check('parent-low')
            assert all((root / 'nested' / 'file').read_text(encoding='utf-8') == 'owned diagnostic' for root in roots)
            result['matched'] = all(check['matched'] for check in result['checks'])
            result['phase'] = 'complete'
        except BaseException as error:
            result['error_type'] = type(error).__name__
            result['winerror'] = getattr(error, 'winerror', None)
        finally:
            for handle in reversed(handles):
                api.close(handle)
    return result


def main():
    if os.name != 'nt':
        print(json.dumps({'available': False, 'reason': 'Windows only'}))
        return
    api = Api()
    with api.privileges() as available:
        if not available:
            print(json.dumps({'available': False, 'reason': 'Required operator rights absent; no UAC requested',
                              'privileges': api.privilege_report}))
            if os.environ.get('GITHUB_ACTIONS', '').lower() == 'true':
                raise SystemExit(2)
            return
        directory = C.create_unicode_buffer(32768)
        size = api.get_system(directory, len(directory))
        api.check(size and size < len(directory))
        editor = str(Path(directory.value) / 'icacls.exe')
        results = [run_case(api, editor, scenario, source)
                   for scenario in ('legacy', 'medium', 'audit')
                   for source in ('native', 'kernel', 'win32')]
        query_cases = [case for case in results if case['snapshot_source'] == 'native']
        checks = {
            'all_cases_completed': all(case['phase'] == 'complete' for case in results),
            'native_and_kernel_restore_future_semantics': all(case.get('matched') for case in results
                if case['snapshot_source'] in ('native', 'kernel')),
            'queries_do_not_mutate_native_state': all(case.get('query_order') and
                all(item['native_read_stable'] and item['kernel_components_equal'] for item in case['query_order'])
                for case in query_cases),
            'medium_and_audit_expose_reconstruction': all(any(not item['win32_components_equal']
                for item in case.get('query_order', [])) for case in query_cases if case['scenario'] in ('medium', 'audit')),
            'reconstructed_snapshot_restore_diverges': all(not case.get('matched', True) for case in results
                if case['snapshot_source'] == 'win32' and case['scenario'] in ('medium', 'audit')),
        }
        print(json.dumps({'available': True, 'checks': checks, 'results': results}, indent=2))
        if not all(checks.values()):
            raise SystemExit(1)


if __name__ == '__main__':
    main()
