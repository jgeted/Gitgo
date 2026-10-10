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
    _fields_ = [("count", W.DWORD), ("entries", Entry * 3)]


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
            desired.count = 3
            for i, name in enumerate(("SeSecurityPrivilege","SeRestorePrivilege","SeBackupPrivilege")):
                self.check(lookup(None,name,C.byref(desired.entries[i].luid)))
                desired.entries[i].attributes = 2
            C.set_last_error(0)
            self.check(adjust(token,False,C.byref(desired),C.sizeof(previous),C.byref(previous),C.byref(needed)))
            changed = True
            adjust_error = C.get_last_error()
            restricted = fn(self.a,"IsTokenRestricted",[W.HANDLE],W.BOOL)
            info = fn(self.a,"GetTokenInformation",[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.POINTER(W.DWORD)],W.BOOL)
            size = W.DWORD()
            info(token,3,None,0,C.byref(size))
            buffer = C.create_string_buffer(size.value)
            self.check(info(token,3,buffer,size.value,C.byref(size)))
            enabled = []
            count = W.DWORD.from_buffer(buffer).value
            for i,name in enumerate(("SeSecurityPrivilege","SeRestorePrivilege","SeBackupPrivilege")):
                luid = desired.entries[i].luid
                attributes = None
                for j in range(count):
                    entry = Entry.from_buffer(buffer,4+j*C.sizeof(Entry))
                    if entry.luid.low==luid.low and entry.luid.high==luid.high:
                        attributes=entry.attributes;break
                enabled.append({"name":name,"attributes":attributes,"enabled":attributes is not None and bool(attributes&2)})
            elevated=W.DWORD()
            self.check(info(token,20,C.byref(elevated),C.sizeof(elevated),C.byref(size)))
            self.privilege_report={"adjust_error":adjust_error,"restricted":bool(restricted(token)),"elevated":bool(elevated.value),"privileges":enabled}
            yield adjust_error != 1300
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

    def snapshot(self,h,query=0x10000):
        sd=C.c_void_p()
        status=self.get(h,1,query,None,None,None,None,C.byref(sd))
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
            print(json.dumps({"available":False,"reason":"Required backup/security/restore privileges unavailable; no UAC requested","privileges":api.privilege_report,"docs":DOCS}));return
        directory=C.create_unicode_buffer(32768)
        size=api.get_system(directory,len(directory));api.check(size and size<len(directory))
        editor=str(Path(directory.value)/"icacls.exe")
        for query in (0x10000,0xf):
            for mode in ("nt-backup","nt-all","backupwrite"):
                for changed in (False,True):
                    result={"mode":mode,"query":hex(query),"changed":changed,"phase":"create"}
                    with tempfile.TemporaryDirectory(prefix="gitgo_acl_backup_") as temp:
                        root=Path(temp).resolve()/"workspace"
                        root.mkdir();(root/"nested").mkdir();(root/"nested"/"file").write_text("owned diagnostic")
                        paths=[root,root/"nested",root/"nested"/"file"]
                        handles=[]
                        try:
                            result["phase"]="open"
                            for index,path in enumerate(paths):
                                result["object_index"]=index
                                handles.append(api.handle(path))
                            result["phase"]="snapshot"
                            before=[]
                            for index,h in enumerate(handles):
                                result["object_index"]=index
                                before.append(api.snapshot(h,query))
                            result["before"]=[summary(r) for r in before]
                            if changed:
                                result["phase"]="grant"
                                subprocess.run([editor,str(root),"/grant","*S-1-1-0:(OI)(CI)R"],check=True,capture_output=True)
                                result["phase"]="label"
                                subprocess.run([editor,str(root),"/setintegritylevel","(OI)(CI)L"],check=True,capture_output=True)
                            result["phase"]="restore"
                            for index,(h,record) in enumerate(zip(handles,before)):
                                result["object_index"]=index
                                api.restore(h,record["raw"],mode)
                            result["phase"]="verify"
                            after=[]
                            for index,h in enumerate(handles):
                                result["object_index"]=index
                                after.append(api.snapshot(h,query))
                            result["matched"]=all(a["control"]==b["control"] and a["sddl"]==b["sddl"] for a,b in zip(before,after))
                            result["binary_matched"]=all(a["raw"]==b["raw"] for a,b in zip(before,after))
                            result["records"]=[{"before":summary(a),"after":summary(b)} for a,b in zip(before,after)]
                            if (root/"nested"/"file").read_text()!="owned diagnostic":raise AssertionError("File content changed")
                            result["phase"]="complete"
                        except BaseException as e:
                            result["error_type"]=type(e).__name__;result["winerror"]=getattr(e,"winerror",None)
                        finally:
                            for h in reversed(handles):api.close(h)
                    results.append(result)
    print(json.dumps({"available":True,"privileges":api.privilege_report,"results":results,"docs":DOCS},indent=2))





def acl_aces(raw,offset):
    position=int.from_bytes(raw[offset:offset+4],"little")
    if not position:return None
    count=int.from_bytes(raw[position+4:position+6],"little")
    index=position+8
    entries=[]
    for _ in range(count):
        size=int.from_bytes(raw[index+2:index+4],"little")
        entries.append(raw[index:index+size].hex());index+=size
    return entries


def semantic(record):
    control=record["control"]
    sacl=acl_aces(record["raw"],12)
    sddl=record["sddl"]
    if not sacl:
        # Only no-audit/no-label representation: preserve AI, AR and P bits.
        control &= ~0x10
        if "S:" in sddl:sddl=sddl.split("S:",1)[0]
    return {"control":control,"sddl":sddl,"dacl_aces":acl_aces(record["raw"],16),"sacl_aces":sacl or []}


def tree_records(api,root):
    paths=[root,*sorted(root.rglob("*"))]
    result=[]
    for path in paths:
        h=api.handle(path)
        try: result.append((str(path.relative_to(root)),api.snapshot(h,0xf)))
        finally: api.close(h)
    return result


def compare_trees(api,left,right):
    before,after=tree_records(api,left),tree_records(api,right)
    differences=[]
    for (pa,a),(pb,b) in zip(before,after):
        if pa!=pb or semantic(a)!=semantic(b):
            differences.append({"relative_path":pa,"before":summary(a),"after":summary(b)})
    return {"matched":len(before)==len(after) and not differences,"object_count":len(before),"differences":differences,
            "representation_only":[{"relative_path":pa,"before_control":a["control"],"after_control":b["control"]}
                 for (pa,a),(_,b) in zip(before,after) if a["control"]!=b["control"] and semantic(a)==semantic(b)]}


def initialise_sacl(api,root,scenario):
    if scenario=="legacy":return
    convert=fn(api.a,"ConvertStringSecurityDescriptorToSecurityDescriptorW",[W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.c_void_p],W.BOOL)
    for path in [root,*sorted(root.rglob("*"))]:
        flags="OICI" if path.is_dir() else ""
        label=f"(ML;{flags};NW;;;ME)"
        audit=f"(AU;{flags}SAFA;FR;;;WD)" if scenario in {"audit","protected-sacl"} else ""
        text="S:"+("P" if scenario=="protected-sacl" else "")+audit+label
        sd=C.c_void_p();api.check(convert(text,1,C.byref(sd),None))
        h=api.handle(path)
        try:
            status=api.set(h,8,sd)
            if status:raise C.WinError(api.error(status))
        finally:api.close(h);api.free(sd)


def ordinary_backup(api):
    result={"mode":"ordinary-token-backupwrite","phase":"create"}
    with tempfile.TemporaryDirectory(prefix="gitgo_acl_ordinary_") as temp:
        root=Path(temp).resolve()/"workspace";root.mkdir()
        h=None
        try:
            result["phase"]="open"
            h=api.open(str(root),0xe0001,3,None,3,0x02200000,None)
            if h==C.c_void_p(-1).value:raise C.WinError(C.get_last_error())
            result["phase"]="snapshot"
            before=api.snapshot(h,1|2|4|16)
            result["phase"]="restore"
            api.restore(h,before["raw"],"backupwrite")
            result["phase"]="verify"
            after=api.snapshot(h,1|2|4|16)
            result["semantic_matched"]=semantic(before)==semantic(after)
            result["before"]=summary(before);result["after"]=summary(after)
            result["phase"]="complete"
        except BaseException as e:
            result["error_type"]=type(e).__name__;result["winerror"]=getattr(e,"winerror",None)
        finally:
            if h and h!=C.c_void_p(-1).value:api.close(h)
    return result


def differential_main():
    if os.name!="nt":print(json.dumps({"available":False,"reason":"Windows only"}));return
    api=Api();results=[]
    ordinary=ordinary_backup(api)
    with api.privileges() as available:
        if not available:
            print(json.dumps({"available":False,"ordinary":ordinary,"privileges":api.privilege_report,"docs":DOCS}));return
        directory=C.create_unicode_buffer(32768)
        size=api.get_system(directory,len(directory));api.check(size and size<len(directory))
        editor=str(Path(directory.value)/"icacls.exe")
        def edit(path,*args):subprocess.run([editor,str(path),*args],check=True,capture_output=True)
        for scenario in ("legacy","medium","audit","protected-sacl"):
            result={"scenario":scenario,"phase":"create","checks":[]}
            with tempfile.TemporaryDirectory(prefix="gitgo_acl_future_") as temp:
                parent=Path(temp).resolve()
                roots=[]
                for name in ("baseline","restored"):
                    outer=parent/name;outer.mkdir();root=outer/"workspace";root.mkdir()
                    (root/"nested").mkdir();(root/"nested"/"file").write_text("owned diagnostic")
                    roots.append(root)
                left,right=roots
                handles=[]
                try:
                    result["phase"]="initialise"
                    for root in roots:initialise_sacl(api,root,scenario)
                    result["checks"].append({"stage":"initial",**compare_trees(api,left,right)})
                    result["phase"]="snapshot"
                    paths=[right,*sorted(right.rglob("*"))]
                    for path in paths:handles.append(api.handle(path))
                    originals=[api.snapshot(h,0xf) for h in handles]
                    result["phase"]="mutate"
                    edit(right,"/grant","*S-1-1-0:(OI)(CI)R")
                    edit(right,"/setintegritylevel","(OI)(CI)L")
                    result["phase"]="restore"
                    for h,record in zip(handles,originals):api.restore(h,record["raw"],"backupwrite")
                    for h in reversed(handles):api.close(h)
                    handles=[]
                    result["checks"].append({"stage":"restored",**compare_trees(api,left,right)})
                    result["phase"]="future-parent-add"
                    for root in roots:edit(root.parent,"/grant","*S-1-5-7:(OI)(CI)R")
                    result["checks"].append({"stage":"parent-add",**compare_trees(api,left,right)})
                    result["phase"]="future-parent-label"
                    for root in roots:edit(root.parent,"/setintegritylevel","(OI)(CI)M")
                    result["checks"].append({"stage":"parent-medium",**compare_trees(api,left,right)})
                    result["phase"]="future-new-children"
                    for root in roots:
                        (root/"new-directory").mkdir();(root/"new-directory"/"new-file").write_text("future object")
                        (root/"nested"/"new-file").write_text("future nested object")
                    result["checks"].append({"stage":"new-children",**compare_trees(api,left,right)})
                    result["phase"]="future-parent-remove"
                    for root in roots:edit(root.parent,"/remove:g","*S-1-5-7")
                    result["checks"].append({"stage":"parent-remove",**compare_trees(api,left,right)})
                    result["phase"]="future-parent-low"
                    for root in roots:edit(root.parent,"/setintegritylevel","(OI)(CI)L")
                    result["checks"].append({"stage":"parent-low",**compare_trees(api,left,right)})
                    result["phase"]="complete"
                    result["matched"]=all(c["matched"] for c in result["checks"])
                except BaseException as e:
                    result["error_type"]=type(e).__name__;result["winerror"]=getattr(e,"winerror",None)
                finally:
                    for h in reversed(handles):api.close(h)
            results.append(result)
    print(json.dumps({"available":True,"ordinary":ordinary,"privileges":api.privilege_report,"results":results,"docs":DOCS},indent=2))


if __name__=="__main__":differential_main()
