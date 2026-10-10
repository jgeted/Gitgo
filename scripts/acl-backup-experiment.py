"""Isolated full security descriptor restore experiment; never production code."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

DOCS = [
    "https://learn.microsoft.com/en-us/windows/win32/secauthz/security-information",
    "https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-backupwrite",
    "https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id",
    "https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject",
]


def fn(dll, name, args, result):
    f = getattr(dll, name)
    f.argtypes, f.restype = args, result
    return f


class Luid(C.Structure):
    _fields_ = [("low", W.DWORD), ("high", W.LONG)]


class Entry(C.Structure):
    _fields_ = [("luid", Luid), ("attributes", W.DWORD)]


class Privileges(C.Structure):
    _fields_ = [("count", W.DWORD), ("entries", Entry * 2)]


class Api:
    def __init__(self):
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self.a = C.WinDLL("advapi32", use_last_error=True)
        self.n = C.WinDLL("ntdll", use_last_error=True)
        self.close = fn(self.k, "CloseHandle", [W.HANDLE], W.BOOL)
        self.free = fn(self.k, "LocalFree", [C.c_void_p], C.c_void_p)
        self.open = fn(self.k, "CreateFileW", [W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE], W.HANDLE)
        self.get = fn(self.a, "GetSecurityInfo", [W.HANDLE,C.c_int,W.DWORD,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p)],W.DWORD)
        self.length = fn(self.a, "GetSecurityDescriptorLength", [C.c_void_p],W.DWORD)
        self.control = fn(self.a, "GetSecurityDescriptorControl", [C.c_void_p,C.POINTER(W.WORD),C.POINTER(W.DWORD)],W.BOOL)
        self.text = fn(self.a, "ConvertSecurityDescriptorToStringSecurityDescriptorW", [C.c_void_p,W.DWORD,W.DWORD,C.POINTER(W.LPWSTR),C.c_void_p],W.BOOL)
        self.set = fn(self.n, "NtSetSecurityObject", [W.HANDLE,W.DWORD,C.c_void_p],C.c_long)
        self.error = fn(self.n, "RtlNtStatusToDosError", [C.c_long],W.DWORD)
        self.backup = fn(self.k, "BackupWrite", [W.HANDLE,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),W.BOOL,W.BOOL,C.POINTER(C.c_void_p)], W.BOOL)
        self.get_system = fn(self.k, "GetSystemDirectoryW", [W.LPWSTR,W.UINT],W.UINT)

    @staticmethod
    def check(ok):
        if not ok:
            raise C.WinError(C.get_last_error())

    @contextmanager
    def privileges(self):
        token = W.HANDLE()
        open_token = fn(self.a,"OpenProcessToken",[W.HANDLE,W.DWORD,C.POINTER(W.HANDLE)],W.BOOL)
        lookup = fn(self.a,"LookupPrivilegeValueW",[W.LPCWSTR,W.LPCWSTR,C.POINTER(Luid)],W.BOOL)
        adjust = fn(self.a,"AdjustTokenPrivileges",[W.HANDLE,W.BOOL,C.c_void_p,W.DWORD,C.c_void_p,C.c_void_p],W.BOOL)
        self.check(open_token(C.c_void_p(-1),0x28,C.byref(token)))
        previous, desired, needed = Privileges(), Privileges(), W.DWORD()
        changed = False
        try:
            desired.count = 2
            for i, name in enumerate(("SeSecurityPrivilege","SeRestorePrivilege")):
                self.check(lookup(None,name,C.byref(desired.entries[i].luid)))
                desired.entries[i].attributes = 2
            C.set_last_error(0)
            self.check(adjust(token,False,C.byref(desired),C.sizeof(previous),C.byref(previous),C.byref(needed)))
            changed = True
            yield C.get_last_error() != 1300
        finally:
            if changed:
                self.check(adjust(token,False,C.byref(previous),0,None,None))
            self.close(token)

    def handle(self,path):
        # READ_DATA/LIST_DIRECTORY, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
        # ACCESS_SYSTEM_SECURITY. No delete sharing, no async I/O.
        h=self.open(str(path),0x010e0001,3,None,3,0x02200000,None)
        if h == C.c_void_p(-1).value:
            raise C.WinError(C.get_last_error())
        return h

    def snapshot(self,h):
        sd=C.c_void_p()
        status=self.get(h,1,0x10000,None,None,None,None,C.byref(sd))
        if status:
            raise C.WinError(status)
        try:
            raw=C.string_at(sd,self.length(sd))
            control,rev=W.WORD(),W.DWORD()
            self.check(self.control(sd,C.byref(control),C.byref(rev)))
            txt=W.LPWSTR()
            self.check(self.text(sd,1,0xf,C.byref(txt),None))
            try: sddl=txt.value
            finally: self.free(C.cast(txt,C.c_void_p))
            return {"raw":raw,"control":control.value,"sddl":sddl}
        finally:
            self.free(sd)

    def restore(self,h,raw,mode):
        buffer=C.create_string_buffer(raw)
        if mode != "backupwrite":
            flags=0x10000 if mode == "nt-backup" else 0xf
            status=self.set(h,flags,buffer)
            if status != 0:
                raise C.WinError(self.error(status))
            return
        payload=struct.pack("<IIqI",3,2,len(raw),0)+raw
        data=C.create_string_buffer(payload)
        written=W.DWORD()
        context=C.c_void_p()
        try:
            self.check(self.backup(h,data,len(payload),C.byref(written),False,True,C.byref(context)))
            if written.value != len(payload):
                raise OSError("BackupWrite partial stream: "+str(written.value))
        finally:
            self.check(self.backup(h,None,0,C.byref(written),True,True,C.byref(context)))


def safe(sddl):
    return re.sub(r"S-1-[0-9-]+",lambda m:"principal-"+hashlib.sha256(m[0].encode()).hexdigest()[:12],sddl)


def summary(record):
    return {"control":record["control"],"sddl":safe(record["sddl"]),"binary_sha256":hashlib.sha256(record["raw"]).hexdigest()}


def main():
    if os.name != "nt":
        print(json.dumps({"available":False,"reason":"Windows only"}));return
    api=Api()
    results=[]
    with api.privileges() as available:
        if not available:
            print(json.dumps({"available":False,"reason":"SeSecurityPrivilege/SeRestorePrivilege unavailable; no UAC requested","docs":DOCS}));return
        directory=C.create_unicode_buffer(32768)
        size=api.get_system(directory,len(directory));api.check(size and size<len(directory))
        editor=str(Path(directory.value)/"icacls.exe")
        for mode in ("nt-backup","nt-all","backupwrite"):
            for changed in (False,True):
                result={"mode":mode,"changed":changed}
                with tempfile.TemporaryDirectory(prefix="gitgo_acl_backup_") as temp:
                    root=Path(temp).resolve()/"workspace"
                    root.mkdir();(root/"nested").mkdir();(root/"nested"/"file").write_text("owned diagnostic")
                    paths=[root,root/"nested",root/"nested"/"file"]
                    handles=[]
                    try:
                        handles=[api.handle(p) for p in paths]
                        before=[api.snapshot(h) for h in handles]
                        if changed:
                            subprocess.run([editor,str(root),"/grant","*S-1-1-0:(OI)(CI)R"],check=True,capture_output=True)
                            subprocess.run([editor,str(root),"/setintegritylevel","(OI)(CI)L"],check=True,capture_output=True)
                        for h,record in zip(handles,before):
                            api.restore(h,record["raw"],mode)
                        after=[api.snapshot(h) for h in handles]
                        result["matched"]=all(a["control"]==b["control"] and a["sddl"]==b["sddl"] for a,b in zip(before,after))
                        result["binary_matched"]=all(a["raw"]==b["raw"] for a,b in zip(before,after))
                        result["records"]=[{"before":summary(a),"after":summary(b)} for a,b in zip(before,after)]
                        if (root/"nested"/"file").read_text()!="owned diagnostic":raise AssertionError("File content changed")
                    except BaseException as e:
                        result["error_type"]=type(e).__name__;result["winerror"]=getattr(e,"winerror",None)
                    finally:
                        for h in reversed(handles):api.close(h)
                results.append(result)
    print(json.dumps({"available":True,"results":results,"docs":DOCS},indent=2))


if __name__=="__main__":main()
