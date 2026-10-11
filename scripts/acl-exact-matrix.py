"""Bounded restore diagnostics on owned temporary trees, not production code."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

_source = Path(os.environ.get("GITGO_ACL_EXPERIMENT", Path(__file__).with_name("acl-backup-experiment.py")))
_spec = importlib.util.spec_from_file_location("gitgo_acl_experiment", _source)
b = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(b)


class Api(b.Api):
    def __init__(self):
        super().__init__()
        self.query = b.fn(self.n, "NtQuerySecurityObject", [W.HANDLE, W.DWORD, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)], C.c_long)
        self.convert = b.fn(self.a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p], W.BOOL)
        self.set_control = b.fn(self.a, "SetSecurityDescriptorControl", [C.c_void_p, W.WORD, W.WORD], W.BOOL)

    def native_snapshot(self, handle, flags=0x1ff):
        needed = W.DWORD()
        self.query(handle, flags, None, 0, C.byref(needed))
        if not 20 <= needed.value <= 1024 * 1024:
            raise ValueError("Unexpected native descriptor length")
        raw = C.create_string_buffer(needed.value)
        status = self.query(handle, flags, raw, len(raw), C.byref(needed))
        if status:
            raise C.WinError(self.error(status))
        control, revision = W.WORD(), W.DWORD()
        self.check(self.control(raw, C.byref(control), C.byref(revision)))
        text = W.LPWSTR()
        self.check(self.text(raw, 1, 0x1ff, C.byref(text), None))
        try:
            return {"raw": raw.raw[:needed.value], "control": control.value, "sddl": text.value}
        finally:
            self.free(C.cast(text, C.c_void_p))

    def native_set(self, handle, raw, flags):
        raw_buffer = C.create_string_buffer(raw)
        status = self.set(handle, flags, raw_buffer)
        if status:
            raise C.WinError(self.error(status))

    def fixture_post_descriptor(self, original, directory):
        # The matrix fixtures contain ordinary ACEs only. This SDDL builder is
        # deliberately diagnostic, not a proposed general production compiler.
        value = original["sddl"]
        dacl, separator, sacl = value.partition("S:")
        inherited = "OICI" if directory else ""
        dacl += f"(A;{inherited};FR;;;WD)"
        if "(ML;" in sacl:
            sacl = re.sub(r"(\(ML;[^)]*;;;)(?:ME|S-1-16-8192)(\))", r"\1LW\2", sacl)
        else:
            sacl += f"(ML;{inherited};NW;;;LW)"
        descriptor = C.c_void_p()
        self.check(self.convert(dacl + "S:" + sacl, 1, C.byref(descriptor), None))
        try:
            # Preserve the original six DACL/SACL inheritance/protection bits,
            # including legacy AUTO_INHERITED state even on an absent SACL.
            self.check(self.set_control(descriptor, 0x3f00, original["control"] & 0x3f00))
            return C.string_at(descriptor, self.length(descriptor))
        finally:
            self.free(descriptor)


def binary_components(record):
    raw = record["raw"]
    def sid(header_offset):
        offset = int.from_bytes(raw[header_offset:header_offset+4], "little")
        if not offset:
            return None
        size = 8 + 4 * raw[offset+1]
        return raw[offset:offset+size].hex()
    def acl(header_offset):
        offset = int.from_bytes(raw[header_offset:header_offset+4], "little")
        if not offset:
            return None
        return {"revision": raw[offset], "aces": b.acl_aces(raw, header_offset)}
    # Keep DEFAULTED, AUTO_INHERIT_REQ, AUTO_INHERITED, PROTECTED, RM_CONTROL.
    return {"revision": raw[0], "rm_control": raw[1], "control": record["control"],
            "owner": sid(4), "group": sid(8), "sacl": acl(12), "dacl": acl(16)}


def record_summary(record):
    result = b.summary(record)
    result.update({"revision": record["raw"][0], "rm_control": record["raw"][1], "length": len(record["raw"])})
    return result


def observations(api, outer):
    result = {}
    for path in [outer, *sorted(outer.rglob("*"))]:
        handle = api.handle(path)
        try:
            kinds = {}
            for name, callback in (
                ("win32-all", lambda: api.snapshot(handle, 0x1ff)),
                ("win32-backup", lambda: api.snapshot(handle, 0x10000)),
                ("native-all", lambda: api.native_snapshot(handle, 0x1ff)),
                ("native-backup", lambda: api.native_snapshot(handle, 0x10000)),
            ):
                try:
                    kinds[name] = callback()
                except (OSError, ValueError) as error:
                    kinds[name] = {"error_type": type(error).__name__, "winerror": getattr(error, "winerror", None)}
            result[str(path.relative_to(outer))] = kinds
        finally:
            api.close(handle)
    return result


def public_observations(records):
    return {path: {kind: record_summary(value) if "raw" in value else value
                   for kind, value in kinds.items()} for path, kinds in records.items()}


def paired_comparison(api, left, right):
    a, z = observations(api, left), observations(api, right)
    differences, binary_differences, unavailable = [], [], []
    for path in sorted(set(a) | set(z)):
        if path not in a or path not in z:
            differences.append({"path": path, "reason": "inventory"}); continue
        for kind in a[path]:
            x, y = a[path][kind], z[path][kind]
            if "raw" not in x or "raw" not in y:
                unavailable.append({"path": path, "kind": kind, "left": x, "right": y}); continue
            if x["raw"] != y["raw"]:
                binary_differences.append({"path": path, "kind": kind, "left": record_summary(x), "right": record_summary(y)})
            if binary_components(x) != binary_components(y):
                differences.append({"path": path, "kind": kind, "left": record_summary(x), "right": record_summary(y)})
    return {"matched": not differences and not unavailable, "object_count": len(a),
            "differences": differences, "binary_differences": binary_differences, "unavailable": unavailable}


def run_case(api, editor, scenario, mode):
    result = {"scenario": scenario, "mode": mode, "phase": "create", "checks": []}
    handles = []
    with tempfile.TemporaryDirectory(prefix="gitgo_acl_exact_") as temporary:
        parent = Path(temporary).resolve()
        roots = []
        for name in ("baseline", "restored"):
            outer = parent / name; outer.mkdir()
            root = outer / "workspace"; root.mkdir()
            (root / "nested").mkdir()
            (root / "nested" / "file").write_text("owned diagnostic", encoding="utf-8")
            roots.append(root)
        left, right = roots
        def edit(path, *arguments):
            subprocess.run([editor, str(path), *arguments], check=True, capture_output=True, timeout=20)
        def check(stage):
            result["checks"].append({"stage": stage, **paired_comparison(api, left.parent, right.parent)})
        try:
            result["phase"] = "initialise"
            for root in roots:
                b.initialise_sacl(api, root, scenario)
            check("initial")
            result["initial"] = public_observations(observations(api, right.parent))
            paths = [right, *sorted(right.rglob("*"))]
            for path in paths:
                handles.append(api.handle(path))
            originals = [api.native_snapshot(handle, 0x10000) for handle in handles]
            if scenario != "legacy":
                assert all("(ML;" in record["sddl"] and ";;;ME)" in record["sddl"] for record in originals), "Missing original Medium MIC"
            result["phase"] = "mutate"
            if mode == "backup-apply-restore":
                for path, handle, record in zip(paths, handles, originals):
                    api.restore(handle, api.fixture_post_descriptor(record, path.is_dir()), "backupwrite")
            elif mode != "backup-noop":
                edit(right, "/grant", "*S-1-1-0:(OI)(CI)R")
                edit(right, "/setintegritylevel", "(OI)(CI)L")
            result["phase"] = "restore"
            pairs = list(zip(handles, originals))
            if mode == "backup-child-first":
                pairs.reverse()
            for handle, record in pairs:
                raw = record["raw"]
                if mode == "nt-all-1f":
                    api.native_set(handle, raw, 0x1f)
                elif mode == "nt-backup-1001f":
                    api.native_set(handle, raw, 0x1001f)
                else:
                    api.restore(handle, raw, "backupwrite")
                    if mode in {"backup-then-sacl", "backup-sacl-dacl"}:
                        api.native_set(handle, raw, 0x18)
                    if mode == "backup-sacl-dacl":
                        api.native_set(handle, raw, 0x4)
            for handle in reversed(handles):
                api.close(handle)
            handles.clear()
            result["phase"] = "immediate"
            check("restored")
            result["immediate"] = public_observations(observations(api, right.parent))
            result["phase"] = "parent-add"
            for root in roots:
                edit(root.parent, "/grant", "*S-1-5-7:(OI)(CI)R")
            check("parent-add")
            result["phase"] = "parent-medium"
            for root in roots:
                edit(root.parent, "/setintegritylevel", "(OI)(CI)M")
            check("parent-medium")
            result["phase"] = "new-children"
            for root in roots:
                (root / "new-directory").mkdir()
                (root / "new-directory" / "new-file").write_text("future object", encoding="utf-8")
                (root / "nested" / "new-file").write_text("future nested object", encoding="utf-8")
            check("new-children")
            result["phase"] = "parent-remove"
            for root in roots:
                edit(root.parent, "/remove:g", "*S-1-5-7")
            check("parent-remove")
            result["phase"] = "parent-low"
            for root in roots:
                edit(root.parent, "/setintegritylevel", "(OI)(CI)L")
            check("parent-low")
            for root in roots:
                assert (root / "nested" / "file").read_text(encoding="utf-8") == "owned diagnostic"
            result["phase"] = "complete"
            result["matched"] = all(item["matched"] for item in result["checks"])
        except BaseException as error:
            result["error_type"] = type(error).__name__
            result["winerror"] = getattr(error, "winerror", None)
        finally:
            for handle in reversed(handles):
                api.close(handle)
    return result


def main():
    if os.name != "nt":
        print(json.dumps({"available": False, "reason": "Windows only"})); return
    api = Api()
    modes = ("nt-all-1f", "nt-backup-1001f", "backup-noop", "backup-parent-first", "backup-child-first", "backup-then-sacl", "backup-sacl-dacl", "backup-apply-restore")
    scenarios = ("legacy", "medium", "audit", "protected-sacl")
    with api.privileges() as available:
        if not available:
            print(json.dumps({"available": False, "privileges": api.privilege_report})); return
        directory = C.create_unicode_buffer(32768)
        size = api.get_system(directory, len(directory))
        api.check(size and size < len(directory))
        editor = str(Path(directory.value) / "icacls.exe")
        results = [run_case(api, editor, scenario, mode) for scenario in scenarios for mode in modes]
        print(json.dumps({"available": True, "privileges": api.privilege_report, "results": results, "docs": b.DOCS}, indent=2))


if __name__ == "__main__":
    main()
