"""Versioned, approval-gated repository ZIP revisions. Static-only; never runs ZIP contents."""
import ast
import difflib
import hashlib
import io
import json
import os
import sqlite3
import uuid
import zipfile
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from app.team_repo_tools import _read_archive

MAX_ZIP = 2 * 1024 * 1024
MAX_REPLACE = 8192

class NewRevision(BaseModel):
    project_id: str = Field(min_length=16, max_length=128)
    file_id: str = Field(min_length=16, max_length=128)
    target_path: str = Field(min_length=1, max_length=240)
    existing_text: str = Field(min_length=1, max_length=MAX_REPLACE)
    replacement_text: str = Field(max_length=MAX_REPLACE)
    reason: str = Field(min_length=12, max_length=2000)
    investigation_id: str | None = None

class ReviewRevision(BaseModel):
    decision: str = Field(pattern='^(approve|reject)$')
    rationale: str = Field(min_length=12, max_length=2000)

class StageRevision(BaseModel):
    acknowledgement: bool = False


def _sha(raw): return hashlib.sha256(raw).hexdigest()


def _revision_preview(raw, target, old, new):
    """Validate exactly one textual change, never write or execute archive members."""
    files,_ = _read_archive(raw)
    matches = [data for name,data in files if name == target]
    if len(matches) != 1: raise ValueError('Target file must already exist in the repository')
    try: before = matches[0].decode('utf-8')
    except UnicodeDecodeError: raise ValueError('Target must be UTF-8 text')
    if before.count(old) != 1: raise ValueError('Expected source text must occur exactly once')
    after = before.replace(old,new,1)
    try: after_bytes = after.encode('utf-8')
    except UnicodeError: raise ValueError('Replacement must be UTF-8')
    if len(after_bytes)>512*1024: raise ValueError('Modified file exceeds safe limit')
    if target.endswith('.py'):
        try: ast.parse(after,filename=target)
        except SyntaxError as exc: raise ValueError(f'Revised Python syntax invalid at line {exc.lineno}')
    diff = ''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='original/'+target,tofile='proposed/'+target))
    if len(diff)>25000: raise ValueError('Proposed difference too large to review')
    return files,after_bytes,{'target_path':target,'original_file_sha256':_sha(matches[0]),
                             'revised_file_sha256':_sha(after_bytes),'diff':diff,
                             'python_syntax_checked':target.endswith('.py'),'runtime_tests_executed':False,
                             'limitations':'Text-only replacement; AST checks are not runtime tests or security certification.'}


def _build_archive(files,target,updated):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        for name,raw in files:
            archive.writestr(name,updated if name==target else raw)
    result=buf.getvalue()
    if len(result)>MAX_ZIP: raise ValueError('Revised ZIP exceeds safe bound')
    _read_archive(result) # Enforce same archive resource/security limits on output.
    return result


def _verify_revision_contents(files, target, updated, staged_zip):
    """Compare exact member paths/bytes independently of ZIP container timestamps.

    Callers must still verify the stored ZIP's SHA-256 and source provenance.
    """
    actual_files, _ = _read_archive(staged_zip)
    expected = {name: (updated if name == target else content) for name, content in files}
    return dict(actual_files) == expected


def register_team_repo_revisions(router,connection,now,actor,member,event,storage):
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS team_repo_revisions(
          id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_id TEXT NOT NULL,
          investigation_id TEXT, source_file_id TEXT NOT NULL, source_sha256 TEXT NOT NULL,
          target_path TEXT NOT NULL, old_text TEXT NOT NULL, new_text TEXT NOT NULL,
          reason TEXT NOT NULL, requested_by TEXT NOT NULL, status TEXT NOT NULL,
          review_by TEXT, review_decision TEXT, review_rationale TEXT,
          staged_by TEXT, staged_file_id TEXT, staged_sha256 TEXT,
          preview_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_repo_revisions_ws ON team_repo_revisions(workspace_id,created_at);
        ''')
        db.execute("UPDATE team_repo_revisions SET status='interrupted',updated_at=? WHERE status='staging'",(now(),))

    root=Path(storage).resolve()
    def _row(db,wid,rid):
        row=db.execute('SELECT * FROM team_repo_revisions WHERE workspace_id=? AND id=?',(wid,rid)).fetchone()
        if not row:raise HTTPException(404,'Revision not found')
        return row
    def _source(db,wid,pid,fid):
        if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,pid)).fetchone():
            raise HTTPException(404,'Shared project missing')
        file=db.execute('SELECT * FROM files WHERE id=? AND project_id=?',(fid,pid)).fetchone()
        if not file:raise HTTPException(404,'Source file missing')
        path=Path(file['storage_path']).resolve()
        if path.parent!=root or path.name!=file['id'] or not path.is_file():
            raise HTTPException(409,'Source storage path invalid or missing')
        if path.stat().st_size>MAX_ZIP:raise HTTPException(413,'Source ZIP exceeds 2 MiB')
        raw=path.read_bytes()
        if _sha(raw)!=file['sha256']:raise HTTPException(409,'Source ZIP integrity mismatch')
        return raw,file
    def _public(row):
        record=dict(row)
        record.pop('old_text',None)
        record.pop('new_text',None)
        record['preview']=json.loads(record.pop('preview_json'))
        return record

    @router.post('/workspaces/{wid}/repo-revisions',status_code=201)
    def propose(wid:str, body:NewRevision,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            raw,stored=_source(db,wid,body.project_id,body.file_id)
            if body.investigation_id and not db.execute('SELECT 1 FROM team_investigations WHERE workspace_id=? AND project_id=? AND id=?',
                    (wid,body.project_id,body.investigation_id)).fetchone():
                raise HTTPException(404,'Shared investigation missing')
            try: _files,_updated,preview=_revision_preview(raw,body.target_path,body.existing_text,body.replacement_text)
            except ValueError as exc:raise HTTPException(422,str(exc))
            rid=uuid.uuid4().hex;stamp=now()
            db.execute('''INSERT INTO team_repo_revisions(id,workspace_id,project_id,investigation_id,source_file_id,source_sha256,target_path,old_text,new_text,reason,requested_by,status,preview_json,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
              (rid,wid,body.project_id,body.investigation_id,body.file_id,stored['sha256'],body.target_path,
               body.existing_text,body.replacement_text,body.reason.strip(),who['id'],'proposed',json.dumps(preview,sort_keys=True),stamp,stamp))
            event(db,wid,who,'repository_revision_proposed',rid,{'source_sha256':stored['sha256'],'target_path':body.target_path})
        return {'id':rid,'status':'proposed','preview':preview,'executed_code':False}

    @router.get('/workspaces/{wid}/repo-revisions')
    def history(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [_public(r) for r in db.execute('SELECT * FROM team_repo_revisions WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]

    @router.get('/workspaces/{wid}/repo-revisions/{rid}')
    def detail(wid:str,rid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return _public(_row(db,wid,rid))

    @router.post('/workspaces/{wid}/repo-revisions/{rid}/review')
    def review(wid:str,rid:str,body:ReviewRevision,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin');row=_row(db,wid,rid)
            if row['status']!='proposed':raise HTTPException(409,'Already reviewed')
            if who['id']==row['requested_by']:raise HTTPException(403,'Independent reviewer required')
            status='approved' if body.decision=='approve' else 'rejected'
            db.execute('''UPDATE team_repo_revisions SET status=?,review_by=?,review_decision=?,review_rationale=?,updated_at=? WHERE id=?''',
              (status,who['id'],body.decision,body.rationale.strip(),now(),rid))
            event(db,wid,who,'repository_revision_reviewed',rid,{'decision':body.decision})
        return {'id':rid,'status':status,'code_executed':False}

    @router.post('/workspaces/{wid}/repo-revisions/{rid}/stage')
    def stage(wid:str,rid:str,body:StageRevision,request:Request):
        who=actor(request)
        if not body.acknowledgement:raise HTTPException(422,'Explicit staging acknowledgement required')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor');row=_row(db,wid,rid)
            if row['status']!='approved':raise HTTPException(409,'Requires approval and cannot stage twice')
            raw,source=_source(db,wid,row['project_id'],row['source_file_id'])
            if source['sha256']!=row['source_sha256']:raise HTTPException(409,'Original source changed')
            db.execute("UPDATE team_repo_revisions SET status='staging',updated_at=? WHERE id=?",(now(),rid))
        artifact_path=None
        try:
            files,updated,preview=_revision_preview(raw,row['target_path'],row['old_text'],row['new_text'])
            if preview!=json.loads(row['preview_json']):raise ValueError('Proposed change no longer matches approved review')
            zip_bytes=_build_archive(files,row['target_path'],updated)
            new_id=uuid.uuid4().hex;artifact_path=root/new_id
            # Exclusive creation; no overwrite of original evidence or another staged artifact.
            with artifact_path.open('xb') as output:
                output.write(zip_bytes)
                output.flush();os.fsync(output.fileno())
            digest=_sha(zip_bytes)
            with connection() as db:
                db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
                row_now=_row(db,wid,rid)
                if row_now['status']!='staging':raise ValueError('Revision state changed during staging')
                # Keep a regular file record for existing team evidence handling and backup.
                db.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)',
                  (new_id,row['project_id'],f'nesson-revision-{rid[:10]}.zip','application/zip',len(zip_bytes),digest,str(artifact_path),'', 'not_extracted',now()))
                db.execute('''UPDATE team_repo_revisions SET status='staged',staged_by=?,staged_file_id=?,staged_sha256=?,updated_at=? WHERE id=?''',
                           (who['id'],new_id,digest,now(),rid))
                event(db,wid,who,'repository_revision_staged',rid,{'artifact_file_id':new_id,'sha256':digest,'runtime_tests_executed':False})
        except Exception:
            if artifact_path is not None:artifact_path.unlink(missing_ok=True)
            with connection() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute("UPDATE team_repo_revisions SET status='failed',updated_at=? WHERE id=? AND status='staging'",(now(),rid))
            raise
        return {'id':rid,'status':'staged','artifact_file_id':new_id,'artifact_sha256':digest,
                'python_syntax_checked':preview['python_syntax_checked'],'runtime_tests_executed':False,
                'source_preserved':True,'execution_provider_connected':False}

    @router.get('/workspaces/{wid}/repo-revisions/{rid}/verify')
    def verify(wid:str,rid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who);row=_row(db,wid,rid)
            if row['status']!='staged':return {'id':rid,'status':row['status'],'verified':False}
            raw,source=_source(db,wid,row['project_id'],row['source_file_id'])
            staged,artifact=_source(db,wid,row['project_id'],row['staged_file_id'])
            if source['sha256']!=row['source_sha256'] or artifact['sha256']!=row['staged_sha256']:
                raise HTTPException(409,'Stored source or artifact hash changed')
            files,updated,preview=_revision_preview(raw,row['target_path'],row['old_text'],row['new_text'])
            # Compare real member names and contents, not ZIP metadata-dependent bytes.
            verified_contents = _verify_revision_contents(files,row['target_path'],updated,staged)
            return {'id':rid,'status':'staged','verified':verified_contents,
                    'original_sha256':row['source_sha256'],'artifact_sha256':row['staged_sha256'],
                    'diff':preview['diff'],'runtime_tests_executed':False,
                    'limitations':'Artifact integrity and Python AST checks are not runtime test results.'}
