'''NESSON Engineering Evidence Dossier: cross-feature truthful audit and recovery planning.

Never invokes arbitrary repository code or AI. Reports saved simulations as calculated
models, worker reports as unaudited claims, and read-only tool results separately.
'''
import json
import uuid
from pathlib import Path
from fastapi import HTTPException,Request
from pydantic import BaseModel,Field
from app.team_unified_intelligence import sha,canonical,compute_brief

class NewDossier(BaseModel):
    investigation_id:str=Field(min_length=16,max_length=128)
    title:str=Field(min_length=6,max_length=150)
    interpretation:str=Field(default='',max_length=3000)

class Recovery(BaseModel):
    title:str=Field(min_length=6,max_length=180)
    rationale:str=Field(min_length=12,max_length=2500)
    priority:str=Field(default='high')

MAX_REVISIONS=30
MAX_SIMULATIONS=30
MAX_EXECUTIONS=30
MAX_HANDOFFS=30

def evidence_snapshot(db,wid,iid,storage):
    brief=compute_brief(db,wid,iid,storage)
    pid=brief['project_id']
    revisions=[]
    for r in db.execute('''SELECT id,investigation_id,status,source_file_id,source_sha256,
          staged_file_id,staged_sha256,target_path,review_decision,created_at
          FROM team_repo_revisions WHERE workspace_id=? AND project_id=?
          AND investigation_id=? ORDER BY created_at DESC,id DESC LIMIT ?''',(wid,pid,iid,MAX_REVISIONS)):
        v=dict(r)
        v['staged_integrity']='not_staged'
        if v['staged_file_id']:
            f=db.execute('SELECT * FROM files WHERE id=? AND project_id=?',(v['staged_file_id'],pid)).fetchone()
            if f:
                p=Path(f['storage_path']).resolve();root=Path(storage).resolve()
                if p.parent==root and p.name==f['id'] and p.is_file() and p.stat().st_size<=2*1024*1024:
                    v['staged_integrity']='intact' if sha(p.read_bytes())==f['sha256']==v['staged_sha256'] else 'changed'
                else:v['staged_integrity']='missing_or_unverifiable'
            else:v['staged_integrity']='missing'
        revisions.append(v)
    rev_ids={r['id'] for r in revisions}
    executions=[]
    # Join by project, then filter against exact investigation's revision IDs.
    for x in db.execute('''SELECT id,revision_id,status,artifact_sha256,selector,manifest_sha256,
       manifest_json,created_at FROM team_execution_requests
       WHERE workspace_id=? AND project_id=? ORDER BY created_at DESC,id DESC LIMIT 100''',(wid,pid)):
        if x['revision_id'] not in rev_ids:continue
        e=dict(x);raw=e.pop('manifest_json')
        e['manifest_integrity']='not_prepared' if not raw else 'intact' if sha(raw.encode())==e['manifest_sha256'] else 'changed'
        e['actual_tests_executed_by_nesson']=False
        executions.append(e)
        if len(executions)>=MAX_EXECUTIONS:break
    request_ids={e['id'] for e in executions}
    handoffs=[]
    for h in db.execute('''SELECT id,request_id,status,artifact_sha256,manifest_sha256,report_sha256,
       report_json,review_decision,created_at FROM team_worker_handoffs
       WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 100''',(wid,)):
        if h['request_id'] not in request_ids:continue
        d=dict(h);raw=d.pop('report_json')
        d['report_record_integrity']='not_reported' if not raw else 'intact' if sha(raw.encode())==d['report_sha256'] else 'changed'
        d['worker_isolation_independently_verified']=False
        handoffs.append(d)
        if len(handoffs)>=MAX_HANDOFFS:break
    simulations=[]
    for s in db.execute('''SELECT id,kind,inputs,outputs,created_at FROM simulations
                  WHERE project_id=? ORDER BY created_at DESC,id DESC LIMIT ?''',(pid,MAX_SIMULATIONS)):
        try:
            ins=json.loads(s['inputs']);outs=json.loads(s['outputs'])
            # Don't include arbitrary huge payloads in the team response.
            if len(s['inputs'])>20000 or len(s['outputs'])>20000:raise ValueError('Exceeds bound')
            status='recorded_calculation_not_runtime_test'
        except (ValueError,TypeError):
            ins=None;outs=None;status='unreadable_or_exceeds_bound'
        simulations.append({'id':s['id'],'kind':s['kind'],'input_sha256':sha(s['inputs'].encode()),
          'output_sha256':sha(s['outputs'].encode()),'inputs':ins,'outputs':outs,'status':status,'created_at':s['created_at']})
    gaps=[]
    if not revisions:gaps.append('No repository revision is associated with this investigation.')
    if any(r['staged_integrity'] not in ('intact','not_staged') for r in revisions):gaps.append('One or more staged repository artifacts fail source integrity checks.')
    if not executions:gaps.append('No approved repository execution request exists for this investigation.')
    if not handoffs:gaps.append('No external worker report is bound to this investigation.')
    if not simulations:gaps.append('No saved project simulation is available for context.')
    gaps.append('Simulation models are not empirical validation or executed repository tests.')
    gaps.append('Signed worker reports, if present, do not independently attest isolation or correctness.')
    gaps.extend(brief['gaps'][:12])
    result={'version':1,'workspace_id':wid,'project_id':pid,'investigation_id':iid,
      'brief_fingerprint':brief['fingerprint'],'source_integrity':brief['integrity'],
      'revisions':revisions,'execution_requests':executions,'worker_handoffs':handoffs,
      'saved_simulations':simulations,'gaps':gaps,'runtime_tests_independently_verified':False,
      'simulation_is_not_test':True,'model_called':False,'code_executed':False}
    result['fingerprint']=sha(canonical(result).encode())
    return result

def register_engineering_dossier(router,connection,now,actor,member,event,storage):
    with connection() as db:db.executescript('''
      CREATE TABLE IF NOT EXISTS team_engineering_dossiers(
        id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,investigation_id TEXT NOT NULL,
        project_id TEXT NOT NULL,title TEXT NOT NULL,interpretation TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,fingerprint TEXT NOT NULL,created_by TEXT NOT NULL,
        created_at TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS idx_engineering_dossier_ws ON team_engineering_dossiers(workspace_id,created_at);
      CREATE TABLE IF NOT EXISTS team_engineering_recovery(
        id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,dossier_id TEXT NOT NULL,
        task_id TEXT NOT NULL,actor_id TEXT NOT NULL,rationale TEXT NOT NULL,created_at TEXT NOT NULL);
    ''')
    def load(db,wid,did):
        r=db.execute('SELECT * FROM team_engineering_dossiers WHERE workspace_id=? AND id=?',(wid,did)).fetchone()
        if not r:raise HTTPException(404,'Dossier not found')
        if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,r['project_id'])).fetchone():
            raise HTTPException(409,'Project is no longer shared')
        s=json.loads(r['snapshot_json'])
        if s.get('fingerprint')!=r['fingerprint'] or sha(canonical({k:v for k,v in s.items() if k!='fingerprint'}).encode())!=r['fingerprint']:
            raise HTTPException(409,'Stored dossier integrity mismatch')
        return r,s
    @router.get('/workspaces/{wid}/engineering/preview/{iid}')
    def preview(wid:str,iid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return evidence_snapshot(db,wid,iid,storage)
    @router.post('/workspaces/{wid}/engineering/dossiers',status_code=201)
    def create(wid:str,body:NewDossier,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            snapshot=evidence_snapshot(db,wid,body.investigation_id,storage)
            did=uuid.uuid4().hex
            db.execute('INSERT INTO team_engineering_dossiers VALUES(?,?,?,?,?,?,?,?,?,?)',
               (did,wid,body.investigation_id,snapshot['project_id'],body.title.strip(),body.interpretation.strip(),
                canonical(snapshot),snapshot['fingerprint'],who['id'],now()))
            event(db,wid,who,'engineering_dossier_saved',did,{'investigation_id':body.investigation_id,'fingerprint':snapshot['fingerprint']})
        return {'id':did,'fingerprint':snapshot['fingerprint'],'saved':True,'code_executed':False}
    @router.get('/workspaces/{wid}/engineering/dossiers')
    def index(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT id,investigation_id,title,fingerprint,created_by,created_at
              FROM team_engineering_dossiers WHERE workspace_id=? ORDER BY created_at DESC,id DESC LIMIT 100''',(wid,))]
    @router.get('/workspaces/{wid}/engineering/dossiers/{did}')
    def detail(wid:str,did:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who);row,snap=load(db,wid,did)
            current=evidence_snapshot(db,wid,row['investigation_id'],storage)
            recovery=[dict(t) for t in db.execute('''SELECT r.id,r.task_id,r.rationale,t.status,t.title,t.priority
              FROM team_engineering_recovery r JOIN collab_tasks t ON t.workspace_id=r.workspace_id AND t.id=r.task_id
              WHERE r.workspace_id=? AND r.dossier_id=? ORDER BY r.created_at DESC LIMIT 100''',(wid,did))]
            return {'id':did,'title':row['title'],'interpretation':row['interpretation'],
              'snapshot':snap,'saved_snapshot_intact':True,'matches_current_evidence':current['fingerprint']==row['fingerprint'],
              'current_fingerprint':current['fingerprint'],'recovery_tasks':recovery,'runtime_tests_verified':False}
    @router.post('/workspaces/{wid}/engineering/dossiers/{did}/recovery',status_code=201)
    def recovery(wid:str,did:str,body:Recovery,request:Request):
        who=actor(request)
        if body.priority not in ('low','normal','high','urgent'):raise HTTPException(422,'Invalid priority')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            row,snap=load(db,wid,did)
            current=evidence_snapshot(db,wid,row['investigation_id'],storage)
            if current['fingerprint']!=row['fingerprint']:raise HTTPException(409,'Dossier evidence changed; refresh before planning recovery')
            tid=uuid.uuid4().hex;rid=uuid.uuid4().hex;stamp=now()
            db.execute('INSERT INTO collab_tasks VALUES(?,?,?,?,?,?,?,?,?,?)',
              (tid,wid,row['project_id'],body.title.strip(),body.rationale.strip(),body.priority,'open',who['id'],stamp,stamp))
            db.execute('INSERT INTO team_engineering_recovery VALUES(?,?,?,?,?,?,?)',
              (rid,wid,did,tid,who['id'],body.rationale.strip(),stamp))
            event(db,wid,who,'engineering_recovery_task',rid,{'dossier_id':did,'task_id':tid})
        return {'id':rid,'task_id':tid,'status':'open','recovery_executed':False,'human_followup_only':True}
