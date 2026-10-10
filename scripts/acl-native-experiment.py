"""Native ACL experiment, exclusively in temporary owned trees."""
from __future__ import annotations
import ctypes as C
from ctypes import wintypes as W
import json, re, hashlib, sys, tempfile, time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import importlib.util
spec=importlib.util.spec_from_file_location('acl',Path(__file__).resolve().parents[1]/'backend/core/windows_acl.py')
acl=importlib.util.module_from_spec(spec);spec.loader.exec_module(acl)
SecurityTree,_fn=acl.SecurityTree,acl._fn

def safe(s):
 return re.sub(r'S-1-[0-9-]+',lambda m:'principal-'+hashlib.sha256(m[0].encode()).hexdigest()[:12],s)
def snap(tree):
 result=[]
 for p,h in tree.handles.items():
  d=C.c_void_p(); s=W.LPWSTR(); c=W.WORD(); r=W.DWORD()
  status=tree.get_security(h,1,4|16,None,None,None,None,C.byref(d))
  if status:raise C.WinError(status)
  try:
   tree.check(tree.to_sddl(d,1,4|16,C.byref(s),None));tree.check(tree.control(d,C.byref(c),C.byref(r)))
   result.append({'sddl':s.value,'control':c.value})
  finally:tree.free(C.cast(s,C.c_void_p));tree.free(d)
 return result

def experiment(mode):
 with tempfile.TemporaryDirectory(prefix='gitgo_acl_exact_') as temp:
  root=Path(temp)/'workspace';root.mkdir();(root/'nested').mkdir();(root/'nested'/'file').write_text('owned')
  with SecurityTree([root]) as tree:
   before=snap(tree);steps=[];descs=[]
   change=_fn(tree.advapi,'SetSecurityDescriptorControl',[C.c_void_p,W.WORD,W.WORD],W.BOOL)
   for item in before:
    d=C.c_void_p();tree.check(tree.from_sddl(item['sddl'],1,C.byref(d),None));descs.append(d)
   pairs=list(zip(tree.handles.values(),descs))
   def apply(items,flags,control=None):
    statuses=[]
    for h,d in items:
     if control is not None:tree.check(change(d,0x3F00,control))
     statuses.append(tree.set_object_security(h,flags,d))
    steps.append({'flags':flags,'statuses':statuses,'state':snap(tree)})
   try:
    if mode=='noop':apply(pairs,4|16)
    elif mode=='label-all-dacl-all':apply(pairs,16);apply(pairs,4)
    elif mode=='label-reverse-dacl-all':apply(list(reversed(pairs)),16);apply(pairs,4)
    elif mode=='label-all-dacl-reverse':apply(pairs,16);apply(list(reversed(pairs)),4)
    elif mode=='label-all-read-dacl-all':
     apply(pairs,16);steps.append({'read_again':snap(tree)});apply(pairs,4)
    elif mode=='label-all-wait-dacl-all':
     apply(pairs,16);time.sleep(0.25);apply(pairs,4);time.sleep(0.25)
    elif mode=='protected-label-all-original-dacl-all':
     apply(pairs,4,0x1000);apply(pairs,16);apply(pairs,4,0)
    elif mode=='label-all-ai-dacl-all':apply(pairs,16);apply(pairs,4,0x400)
    elif mode=='label-all-sacl-ai-dacl-all':apply(pairs,16);apply(pairs,4,0x800)
    elif mode=='backup':apply(pairs,0x10000)
    elif mode=='backup-fields':apply(pairs,0x10000|4|16)
    elif mode=='protected-info':apply(pairs,4|16|0x80000000);apply(pairs,4|0x20000000)
    elif mode=='dacl-only':apply(pairs,4)
    return {'mode':mode,'before':before,'steps':steps,'after':snap(tree)}
   finally:
    for d in descs:tree.free(d)

if __name__=='__main__':
 results=[]
 for mode in ['noop','dacl-only','label-all-dacl-all','label-reverse-dacl-all','label-all-dacl-reverse','label-all-read-dacl-all','label-all-wait-dacl-all','protected-label-all-original-dacl-all','label-all-ai-dacl-all','label-all-sacl-ai-dacl-all','backup','backup-fields','protected-info']:
  try:results.append(experiment(mode))
  except Exception as e:results.append({'mode':mode,'error':str(e)})
 print(safe(json.dumps(results,indent=2)))
