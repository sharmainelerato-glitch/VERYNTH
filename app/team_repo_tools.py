"""Bounded, non-executing repository archive inspection.

These tools read untrusted ZIP *bytes*, never extract, import or execute code.
Reports are evidence for review and do not assert runtime test success.
"""
from __future__ import annotations
import ast
import hashlib
import io
import json
import re
import stat
import struct
import tomllib
import zipfile
from collections import Counter
from pathlib import PurePosixPath

MAX_ARCHIVE_BYTES=2*1024*1024
MAX_FILES=300
MAX_TOTAL_UNCOMPRESSED=12*1024*1024
MAX_ENTRY_BYTES=512*1024
MAX_COMPRESSION_RATIO=150
MAX_RETURNED=100

REPO_TOOLS={
 'repo.manifest':{'description':'Inspect safe ZIP paths, file extensions and file digests without extraction','risk':'read_only'},
 'repo.python_syntax':{'description':'AST-parse Python sources inside ZIP without running them','risk':'read_only'},
 'repo.dependencies':{'description':'Inventory declared requirements and pyproject metadata; no installation','risk':'read_only'},
 'repo.test_discovery':{'description':'Identify probable pytest/unittest files and test functions without executing tests','risk':'read_only'},
 'repo.security_signals':{'description':'Identify selected static Python security review signals; not a vulnerability assessment','risk':'read_only'},
 'repo.import_graph':{'description':'Discover Python imports and static module relationships without importing modules','risk':'read_only'},
 'repo.python_metrics':{'description':'Count Python definitions, AST statements and branching signals; no execution','risk':'read_only'},
}

def validate_repo_parameters(tool,parameters):
    if tool not in REPO_TOOLS:raise ValueError('Unknown repository tool')
    if not isinstance(parameters,dict) or parameters:raise ValueError('Repository inspection accepts no parameters')

def _validate_raw_zip_member_names(archive):
    """Reject unsafe raw ZIP names before zipfile normalizes them on Windows.

    On Windows, ZipInfo replaces backslashes with slashes at construction.
    Inspect central-directory filename bytes instead of trusting normalized
    ZipInfo.filename; do not scan payload bytes, which may contain backslashes.
    """
    fp=archive.fp
    if fp is None:
        raise ValueError('ZIP archive is closed')
    fp.seek(archive.start_dir)
    for _ in archive.infolist():
        header=fp.read(46)
        if len(header)!=46 or header[:4]!=b'PK\x01\x02':
            raise ValueError('Invalid ZIP central-directory entry')
        name_length,extra_length,comment_length=struct.unpack_from('<HHH',header,28)
        raw_name=fp.read(name_length)
        if len(raw_name)!=name_length:
            raise ValueError('Truncated ZIP filename')
        if b'\\' in raw_name or b'\x00' in raw_name:
            raise ValueError('Unsafe archive pathname')
        fp.seek(extra_length+comment_length,1)

def _read_archive(raw):
    if len(raw)>MAX_ARCHIVE_BYTES:raise ValueError('ZIP input exceeds 2 MiB bound')
    try: z=zipfile.ZipFile(io.BytesIO(raw))
    except (zipfile.BadZipFile,ValueError):raise ValueError('Invalid ZIP archive')
    records=[];seen=set();total=0
    with z:
        _validate_raw_zip_member_names(z)
        info=z.infolist()
        if len(info)>MAX_FILES:raise ValueError('Too many ZIP entries')
        for entry in info:
            name=entry.filename
            if '\\' in name or '//' in name or '\x00' in name or name.startswith('/') or re.match(r'^[A-Za-z]:',name):
                raise ValueError('Unsafe archive pathname')
            parts=PurePosixPath(name).parts
            if not parts or any(p in ('..','.','') for p in name.split('/') if p) or '..' in parts:
                raise ValueError('Unsafe archive traversal')
            norm='/'.join(parts).rstrip('/')
            folded=norm.casefold()
            if not norm or folded in seen:raise ValueError('Duplicate or empty archive entry')
            seen.add(folded)
            mode=(entry.external_attr>>16) & 0xFFFF
            if stat.S_ISLNK(mode):raise ValueError('Symbolic links not supported')
            if entry.flag_bits & 0x1:raise ValueError('Encrypted archives not supported')
            if entry.is_dir():continue
            if entry.file_size>MAX_ENTRY_BYTES:raise ValueError('File too large for bounded inspection')
            total+=entry.file_size
            if total>MAX_TOTAL_UNCOMPRESSED:raise ValueError('Uncompressed ZIP limit exceeded')
            if entry.file_size>0 and (entry.file_size/max(1,entry.compress_size))>MAX_COMPRESSION_RATIO:
                raise ValueError('Suspicious archive compression ratio')
            if entry.compress_type not in (zipfile.ZIP_DEFLATED,zipfile.ZIP_STORED):
                raise ValueError('Unsupported ZIP compression method')
            try: data=z.read(entry)
            except (zipfile.BadZipFile,RuntimeError,EOFError):raise ValueError('ZIP member verification failed')
            if len(data)!=entry.file_size:raise ValueError('ZIP member size mismatch')
            records.append((norm,data))
    records.sort(key=lambda x:x[0])
    return records,total

def _text(data):
    try:return data.decode('utf-8-sig')
    except UnicodeDecodeError:return None

def _python(records):return [(name,data) for name,data in records if name.lower().endswith('.py')]

def _parse_py(records):
    good=[];bad=[]
    for name,data in _python(records):
        text=_text(data)
        if text is None:
            bad.append({'path':name,'issue':'Non-UTF8 Python source'})
            continue
        try:tree=ast.parse(text,filename=name)
        except SyntaxError as e:
            bad.append({'path':name,'line':e.lineno,'issue':(e.msg or 'Invalid syntax')[:160]})
            continue
        good.append((name,tree))
    return good,bad

def _dependencies(records):
    candidates=[];requirements=[];projects=[];errors=[]
    for name,data in records:
        base=name.split('/')[-1]
        if base.startswith('requirements') and base.endswith('.txt'):
            candidates.append(name)
            t=_text(data)
            if t is None: errors.append({'path':name,'issue':'Not UTF-8'});continue
            for lineno,line in enumerate(t.splitlines(),1):
                stripped=line.strip()
                if not stripped or stripped.startswith('#'):continue
                if stripped.startswith(('-e ','--','git+','http://','https://')):
                    requirements.append({'path':name,'line':lineno,'declaration':stripped[:160],'needs_manual_review':True})
                else:
                    requirements.append({'path':name,'line':lineno,'declaration':stripped[:160],'needs_manual_review':False})
                if len(requirements)>=MAX_RETURNED:break
        if base=='pyproject.toml':
            candidates.append(name)
            t=_text(data)
            if t is None:errors.append({'path':name,'issue':'Not UTF-8'});continue
            try:
                doc=tomllib.loads(t)
                p=doc.get('project') if isinstance(doc.get('project'),dict) else {}
                deps=p.get('dependencies',[])
                if not isinstance(deps,list):deps=[]
                projects.append({'path':name,'project_name':p.get('name'),'requires_python':p.get('requires-python'),
                                 'dependencies':[str(x)[:160] for x in deps[:MAX_RETURNED]]})
            except (tomllib.TOMLDecodeError,ValueError) as e:errors.append({'path':name,'issue':'TOML parsing failed: '+str(e)[:150]})
    return {'declaration_files':candidates[:MAX_RETURNED], 'requirements':requirements[:MAX_RETURNED],
            'pyproject':projects[:MAX_RETURNED], 'parse_errors':errors[:MAX_RETURNED],
            'installed_or_resolved':False, 'limitations':'Declared dependencies only; no package installation, resolution or vulnerability scanning.'}

def _tests(parsed,bad):
    candidates=[];functions=[]
    for name,tree in parsed:
        base=name.split('/')[-1]
        iscandidate=base.startswith('test_') or base.endswith('_test.py') or '/tests/' in '/'+name
        if iscandidate:candidates.append(name)
        for node in tree.body:
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name.startswith('test_'):
                functions.append({'path':name,'name':node.name,'line':node.lineno})
            if isinstance(node,ast.ClassDef):
                for child in node.body:
                    if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef)) and child.name.startswith('test_'):
                        functions.append({'path':name,'name':node.name+'.'+child.name,'line':child.lineno})
    return {'candidate_test_files':candidates[:MAX_RETURNED], 'discovered_test_functions':functions[:MAX_RETURNED],
            'test_function_count':len(functions),'syntax_errors':bad[:MAX_RETURNED],
            'tests_executed':False,'passed':None,'failed':None,
            'limitations':'Static name-based discovery; collection fixtures, imports and actual test outcomes are not evaluated.'}

def _security(parsed,bad):
    signs=[]
    for name,tree in parsed:
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):continue
            fn=node.func
            dotted=(fn.id if isinstance(fn,ast.Name) else (fn.value.id+'.'+fn.attr if isinstance(fn,ast.Attribute) and isinstance(fn.value,ast.Name) else ''))
            reason=None
            if dotted in ('eval','exec'):reason='dynamic_code_evaluation'
            elif dotted in ('os.system','os.popen'):reason='shell_invocation'
            elif dotted.startswith('pickle.') and dotted in ('pickle.loads','pickle.load'):reason='pickle_deserialization'
            elif dotted in ('subprocess.Popen','subprocess.run','subprocess.call','subprocess.check_output'):
                if any(kw.arg=='shell' and isinstance(kw.value,ast.Constant) and kw.value.value is True for kw in node.keywords):reason='shell_true_subprocess'
            if reason:signs.append({'path':name,'line':node.lineno,'indicator':reason})
    return {'static_indicators':signs[:MAX_RETURNED], 'total_indicators':len(signs),
            'syntax_errors':bad[:MAX_RETURNED], 'classification':'review_signals_only',
            'code_executed':False,'limitations':'Non-exhaustive AST patterns; not a vulnerability scan or proof of exploitability.'}

def _import_graph(parsed,bad):
    edges=[];external=set();file_modules={}
    for name,_ in parsed:
        module=name[:-3].replace('/','.')
        if module.endswith('.__init__'):module=module[:-9]
        file_modules[module]=name
        if module.startswith('src.'):
            file_modules[module[4:]]=name
    for name,tree in parsed:
        for node in ast.walk(tree):
            if isinstance(node,ast.Import):
                for alias in node.names:
                    import_name=alias.name
                    resolved=file_modules.get(import_name) or file_modules.get(import_name.split('.')[0])
                    edges.append({'source':name,'import':import_name,'line':node.lineno,'resolved_in_archive':resolved})
                    if resolved is None:external.add(import_name.split('.')[0])
            elif isinstance(node,ast.ImportFrom):
                imp='.'*node.level+(node.module or '')
                resolved=file_modules.get(node.module or '') if node.level==0 else None
                edges.append({'source':name,'import':imp,'line':node.lineno,'resolved_in_archive':resolved})
                if node.level==0 and resolved is None and node.module:external.add(node.module.split('.')[0])
    return {'imports':edges[:MAX_RETURNED],'total_import_statements':len(edges),
            'unresolved_import_roots':sorted(external)[:MAX_RETURNED], 'syntax_errors':bad[:MAX_RETURNED],
            'limitations':'AST-only import inventory; unresolved means not found in this archive, not necessarily missing or unsafe.'}

def _metrics(parsed,bad):
    files=[];totals={'functions':0,'classes':0,'conditional_branches':0,'loops':0,'exception_handlers':0}
    for name,tree in parsed:
        counts={'functions':0,'classes':0,'conditional_branches':0,'loops':0,'exception_handlers':0}
        for node in ast.walk(tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):counts['functions']+=1
            if isinstance(node,ast.ClassDef):counts['classes']+=1
            if isinstance(node,(ast.If,ast.IfExp,ast.Match)):counts['conditional_branches']+=1
            if isinstance(node,(ast.For,ast.AsyncFor,ast.While)):counts['loops']+=1
            if isinstance(node,ast.ExceptHandler):counts['exception_handlers']+=1
        for key,val in counts.items():totals[key]+=val
        files.append({'path':name,**counts})
    return {'file_metrics':files[:MAX_RETURNED], 'totals':totals, 'syntax_errors':bad[:MAX_RETURNED],
            'limitations':'AST node counts are structural metrics, not executed code coverage, complexity certification or defect prediction.'}

def run_repo_tool(tool,raw,parameters):
    validate_repo_parameters(tool,parameters)
    records,total=_read_archive(raw)
    py,bad=_parse_py(records)
    base={'archive_sha256':hashlib.sha256(raw).hexdigest(),'file_count':len(records),
          'python_file_count':len(_python(records)), 'total_uncompressed_bytes':total,'code_executed':False}
    if tool=='repo.manifest':
        extensions=Counter(PurePosixPath(name).suffix.lower() or '(none)' for name,_ in records)
        result={'files':[{'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in records[:MAX_RETURNED]],
                'extensions':dict(sorted(extensions.items())), 'paths_truncated':len(records)>MAX_RETURNED}
    elif tool=='repo.python_syntax':
        result={'parsed_successfully':len(py),'syntax_errors':bad[:MAX_RETURNED],
                'syntax_valid':not bad, 'limitations':'AST syntax checks only; runtime imports, behavior and tests are not executed.'}
    elif tool=='repo.dependencies':result=_dependencies(records)
    elif tool=='repo.test_discovery':result=_tests(py,bad)
    elif tool=='repo.security_signals':result=_security(py,bad)
    elif tool=='repo.import_graph':result=_import_graph(py,bad)
    elif tool=='repo.python_metrics':result=_metrics(py,bad)
    else:raise ValueError('Unknown tool')
    return {**base,**result}
