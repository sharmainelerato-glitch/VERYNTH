"""Workspace-scoped approval and immutable manifests for FUTURE isolated execution.
No uploaded source is executed. No worker is configured.
"""
import hashlib, json, uuid
from pathlib import Path
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from app.team_repo_tools import _read_archive

POLICY={'network':'disabled','filesystem':'ephemeral-readonly-source','max_wall_seconds':120,'max_cpu_seconds':60,'max_memory_mb':512,'max_output_bytes':65536,'allow_host_secrets':False,'privileged':False}
def digest(b):return hashlib.sha256(b).hexdigest()
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()
class Proposal(BaseModel):
    revision_id:str=Field(min_length=16,max_length=128)
    selector:str=Field(pattern='^(pytest|unittest)$')
    reason:str=Field(min_length=12,max_length=2000)
class Review(BaseModel):
    decision:str=Field(pattern='^(approve|reject)$')
    rationale:str=Field(min_length=12,max_length=2000)
class Prepare(BaseModel):
    acknowledgement:bool=False

def register_team_execution(router,connection,now,actor,member,event,storage):
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS team_execution_requests(
           id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,project_id TEXT NOT NULL,
           revision_id TEXT NOT NULL,artifact_id TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,
           selector TEXT NOT NULL,reason TEXT NOT NULL,requested_by TEXT NOT NULL,status TEXT NOT NULL,
           reviewed_by TEXT,review_rationale TEXT,manifest_json TEXT,manifest_sha256 TEXT,
           created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
           CREATE INDEX IF NOT EXISTS ix_execution_ws ON team_execution_requests(workspace_id,created_at);''')
    root=Path(storage).resolve()
    def get(db,wid,rid):
        r=db.execute('SELECT * FROM team_execution_requests WHERE workspace_id=? AND id=?',(wid,rid)).fetchone()
        if r is None:raise HTTPException(404,'Request not found')
        return r
    def source(db,wid,rev_id):
        r=db.execute('SELECT * FROM team_repo_revisions WHERE workspace_id=? AND id=?',(wid,rev_id)).fetchone()
        if r is None or r['status']!='staged' or not r['staged_file_id']:
            raise HTTPException(409,'A staged approved revision is required')
        f=db.execute('SELECT * FROM files WHERE id=? AND project_id=?',(r['staged_file_id'],r['project_id'])).fetchone()
        if not f:raise HTTPException(409,'Staged file missing')
        path=Path(f['storage_path']).resolve()
        if path.parent!=root or path.name!=f['id'] or not path.is_file():raise HTTPException(409,'Invalid artifact path')
        if path.stat().st_size>2*1024*1024:raise HTTPException(413,'Artifact too large')
        raw=path.read_bytes()
        if digest(raw)!=f['sha256'] or f['sha256']!=r['staged_sha256']:
            raise HTTPException(409,'Artifact hash mismatch')
        try:_read_archive(raw)
        except ValueError as exc:raise HTTPException(422,str(exc))
        return r,f
    def public(row):
        out=dict(row)
        manifest=out.pop('manifest_json',None)
        if manifest:out['manifest']=json.loads(manifest)
        out['actual_tests_executed']=False
        out['execution_provider_connected']=False
        return out
    @router.get('/workspaces/{wid}/execution-capabilities')
    def capabilities(wid:str,request:Request):
        with connection() as db:member(db,wid,actor(request))
        return {'provider_connected':False,'test_execution_available':False,'supported_selectors':['pytest','unittest'],
                'policy':POLICY,'available':['propose','review','prepare_manifest'],
                'message':'Untrusted repository execution unavailable until an isolated worker is integrated.'}
    @router.post('/workspaces/{wid}/execution-requests',status_code=201)
    def propose(wid:str,body:Proposal,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            rev,f=source(db,wid,body.revision_id)
            rid=uuid.uuid4().hex
            db.execute('''INSERT INTO team_execution_requests
                (id,workspace_id,project_id,revision_id,artifact_id,artifact_sha256,selector,reason,requested_by,status,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                (rid,wid,rev['project_id'],rev['id'],f['id'],f['sha256'],body.selector,body.reason,who['id'],'proposed',now(),now()))
            event(db,wid,who,'execution_requested',rid,{'revision_id':rev['id'],'test_selector':body.selector})
        return {'id':rid,'status':'proposed','actual_tests_executed':False}
    @router.get('/workspaces/{wid}/execution-requests')
    def list_requests(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [public(x) for x in db.execute('SELECT * FROM team_execution_requests WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]
    @router.get('/workspaces/{wid}/execution-requests/{rid}')
    def detail(wid:str,rid:str,request:Request):
        who=actor(request)
        with connection() as db:member(db,wid,who);return public(get(db,wid,rid))
    @router.post('/workspaces/{wid}/execution-requests/{rid}/review')
    def review(wid:str,rid:str,body:Review,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin');row=get(db,wid,rid)
            if row['status']!='proposed':raise HTTPException(409,'Already reviewed')
            if who['id']==row['requested_by']:raise HTTPException(403,'Separate reviewer required')
            if body.decision=='approve':
                rev,f=source(db,wid,row['revision_id'])
                if f['id']!=row['artifact_id'] or f['sha256']!=row['artifact_sha256']:
                    raise HTTPException(409,'Artifact changed')
            status='approved' if body.decision=='approve' else 'rejected'
            db.execute('UPDATE team_execution_requests SET status=?,reviewed_by=?,review_rationale=?,updated_at=? WHERE id=?',
                       (status,who['id'],body.rationale,now(),rid))
            event(db,wid,who,'execution_reviewed',rid,{'decision':body.decision})
        return {'id':rid,'status':status,'actual_tests_executed':False}
    @router.post('/workspaces/{wid}/execution-requests/{rid}/prepare')
    def prepare(wid:str,rid:str,body:Prepare,request:Request):
        who=actor(request)
        if not body.acknowledgement:raise HTTPException(422,'Explicit acknowledgement required')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor');row=get(db,wid,rid)
            if row['status']!='approved':raise HTTPException(409,'Approval required; cannot prepare twice')
            rev,f=source(db,wid,row['revision_id'])
            if f['id']!=row['artifact_id'] or f['sha256']!=row['artifact_sha256']:
                raise HTTPException(409,'Source changed')
            manifest={'version':1,'task':'repository_tests','workspace_id':wid,'project_id':row['project_id'],
                      'revision_id':rev['id'],'artifact_id':f['id'],'artifact_sha256':f['sha256'],
                      'selector':row['selector'],'policy':POLICY,'provider':'unconfigured','execution_allowed':False}
            data=encoded(manifest)
            db.execute('''UPDATE team_execution_requests SET status='awaiting_isolated_worker',manifest_json=?,manifest_sha256=?,updated_at=? WHERE id=?''',
                       (data.decode(),digest(data),now(),rid))
            event(db,wid,who,'execution_manifest_prepared',rid,{'manifest_sha256':digest(data),'provider_connected':False})
        return {'id':rid,'status':'awaiting_isolated_worker','manifest':manifest,'manifest_sha256':digest(data),
                'actual_tests_executed':False,'execution_provider_connected':False}
    @router.post('/workspaces/{wid}/execution-requests/{rid}/run')
    def run_disabled(wid:str,rid:str,request:Request):
        who=actor(request)
        with connection() as db:member(db,wid,who,'editor');get(db,wid,rid)
        raise HTTPException(503,'Isolated execution provider unavailable; no code was executed')
