"""Real Windows SACL restoration and future-inheritance regression tests."""
from __future__ import annotations

import base64
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import subprocess
import sys

import pytest

from backend.core.executable_identity import windows_system_executable
from backend.core.windows_acl import SecurityTree
from backend.core.windows_security_descriptor import SecurityDescriptor
from backend.core.windows_security_privileges import security_privileges

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows SACL inheritance')

# Structurally valid synthetic identities only: these tests never create an
# account, profile, AppContainer token, or ACE on a pre-existing user directory.
_PROVISION_SID = 'S-1-15-2-111111111-222222222-333333333-444444444-555555555-666666666-777777777'
_FUTURE_SID = 'S-1-5-21-111111111-222222222-333333333-42001'


@pytest.fixture(autouse=True)
def operator_privileges():
    try:
        with security_privileges():
            pass
    except PermissionError as error:
        if os.environ.get('GITHUB_ACTIONS', '').lower() == 'true':
            pytest.fail('Hosted SACL acceptance requires native operator privileges: ' + str(error))
        pytest.skip('Native SACL management requires an authorized elevated operator token: ' + str(error))


def _function(dll, name, arguments, result):
    function = getattr(dll, name)
    function.argtypes, function.restype = arguments, result
    return function


def _native_state(outer: Path):
    """Query stored descriptors through an independent Win32 API.

    GetSecurityInfo(SE_FILE_OBJECT) can synthesize legacy inheritance flags;
    GetKernelObjectSecurity independently checks the production NtQuery result.
    """
    kernel = C.WinDLL('kernel32', use_last_error=True)
    advapi = C.WinDLL('advapi32', use_last_error=True)
    open_file = _function(kernel, 'CreateFileW',
        [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE], W.HANDLE)
    close = _function(kernel, 'CloseHandle', [W.HANDLE], W.BOOL)
    query = _function(advapi, 'GetKernelObjectSecurity',
        [W.HANDLE, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)], W.BOOL)
    result = {}
    with security_privileges():
        for path in [outer, *sorted(outer.rglob('*'))]:
            handle = open_file(str(path), 0x01020080, 7, None, 3, 0x02200000, None)
            if handle == C.c_void_p(-1).value:
                raise C.WinError(C.get_last_error())
            try:
                needed = W.DWORD()
                assert not query(handle, 0x1ff, None, 0, C.byref(needed))
                assert C.get_last_error() == 122  # ERROR_INSUFFICIENT_BUFFER
                assert 20 <= needed.value <= 1024 * 1024
                buffer = C.create_string_buffer(needed.value)
                if not query(handle, 0x1ff, buffer, len(buffer), C.byref(needed)):
                    raise C.WinError(C.get_last_error())
                assert 20 <= needed.value <= len(buffer)
                result[str(path.relative_to(outer))] = SecurityDescriptor.from_bytes(
                    buffer.raw[:needed.value]).comparison_key()
            finally:
                if not close(handle):
                    raise C.WinError(C.get_last_error())
    return result


def _assert_same(baseline: Path, candidate: Path, stage: str):
    left, right = _native_state(baseline), _native_state(candidate)
    assert left.keys() == right.keys(), f'Inventory differs at {stage}'
    for relative in left:
        assert left[relative] == right[relative], f'Stored security differs at {stage}: {relative}'


def _edit(path: Path, *arguments: str):
    subprocess.run([str(windows_system_executable('System32/icacls.exe')),
                    str(path), *arguments], check=True, capture_output=True, timeout=30)


def _make_member(outer: Path, scenario: str):
    outer.mkdir()
    root = outer / 'workspace'
    (root / 'nested').mkdir(parents=True)
    (root / 'nested' / 'file.txt').write_text('owned SACL fixture', encoding='utf-8')
    if scenario == 'legacy':
        return root
    # The original regression used explicit unprotected Medium/audit SACLs on
    # every level. Install that precise fixture using a separate native setter.
    with SecurityTree([root]) as tree, security_privileges():
        for path in [root, *sorted(root.rglob('*'))]:
            flags = 'OICI' if path.is_dir() else ''
            audit = f'(AU;{flags}SAFA;FR;;;WD)' if scenario in {'audit', 'protected-sacl'} else ''
            text = 'S:' + ('P' if scenario == 'protected-sacl' else '') + audit + f'(ML;{flags};NW;;;ME)'
            descriptor = C.c_void_p()
            tree.check(tree.from_sddl(text, 1, C.byref(descriptor), None))
            try:
                status = tree.set_object_security(tree.handles[str(path)], 8 | 16, descriptor)
                if status:
                    raise C.WinError(tree.status_to_error(status))
            finally:
                tree.free(descriptor)
        records = tree.snapshot()
        assert all('(ML;' in record['sddl'] and ';;;ME)' in record['sddl'] for record in records)
        for record in records:
            value = SecurityDescriptor.from_bytes(base64.b64decode(record['descriptor'], validate=True))
            assert bool(value.control & 0x2000) == (scenario == 'protected-sacl')
            if scenario in {'audit', 'protected-sacl'}:
                assert value.sacl is not None and int.from_bytes(value.sacl[4:6], 'little') == 2
    return root


def _add_children(root: Path, name: str):
    for parent in (root, root / 'nested'):
        directory = parent / ('new_' + name)
        directory.mkdir()
        (directory / 'file.txt').write_text('future SACL fixture', encoding='utf-8')
        (parent / ('new_' + name + '.txt')).write_text('future SACL fixture', encoding='utf-8')


@pytest.mark.parametrize('scenario', ['legacy', 'medium', 'audit', 'protected-sacl'])
def test_production_restore_preserves_future_sacl_inheritance(tmp_path_factory: Path, scenario: str):
    baseline_outer, candidate_outer = tmp_path_factory / 'baseline', tmp_path_factory / 'candidate'
    baseline = _make_member(baseline_outer, scenario)
    candidate = _make_member(candidate_outer, scenario)
    _assert_same(baseline_outer, candidate_outer, 'initial fixture')

    with SecurityTree([candidate]) as tree:
        original = tree.snapshot()
        native = _native_state(candidate)
        for record in original:
            key = SecurityDescriptor.from_bytes(base64.b64decode(record['descriptor'], validate=True)).comparison_key()
            assert key == native[str(Path(record['path']).relative_to(candidate))]
        planned = tree.plan(original, candidate, _PROVISION_SID)
        key = lambda record: SecurityDescriptor.from_bytes(base64.b64decode(record['descriptor'], validate=True)).comparison_key()
        assert [key(record) for record in planned] != [key(record) for record in original]
        boundaries = tree.boundaries()
        tree.restore(planned, expected=original, boundaries=boundaries)
        assert [key(record) for record in tree.snapshot()] == [key(record) for record in planned]
        tree.restore(original, expected=planned, boundaries=boundaries)
    _assert_same(baseline_outer, candidate_outer, 'immediate restore')

    for root in (baseline, candidate):
        _add_children(root, 'restored')
    _assert_same(baseline_outer, candidate_outer, 'new children after restore')

    # Each action changes an ancestor outside the restored tree. Every stage
    # checks full stored owner/group/DACL/SACL/control, including future nodes.
    for stage, arguments in (
        ('parent_dacl_grant', ('/grant', f'*{_FUTURE_SID}:(OI)(CI)R')),
        ('parent_medium', ('/setintegritylevel', '(OI)(CI)M')),
        ('parent_dacl_remove', ('/remove:g', f'*{_FUTURE_SID}')),
        ('parent_low', ('/setintegritylevel', '(OI)(CI)L')),
    ):
        for outer in (baseline_outer, candidate_outer):
            _edit(outer, *arguments)
        _assert_same(baseline_outer, candidate_outer, stage)
        for root in (baseline, candidate):
            _add_children(root, stage)
        _assert_same(baseline_outer, candidate_outer, 'new children after ' + stage)

    for root in (baseline, candidate):
        assert (root / 'nested' / 'file.txt').read_text(encoding='utf-8') == 'owned SACL fixture'
