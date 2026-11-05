"""NESSON external-worker handoff. No user code runs in this module.

The HMAC authenticated report identifies a configured sender, NOT sandbox attestation.
Every external result stays 'reported_unverified' pending independent assessment.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import uuid
from pathlib import Path
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

MAX_LOG=32768
MAX_REPORT=48000

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
def sha(b):return hashlib.sha256(b).hexdigest()
def signing_secret():
    raw=os.environ.get('NESSON_EXTERNAL_WORKER_HMAC_KEY','')
    # Secret must be long and independently provisioned. No self-generated demo keys.
    return raw.encode() if len(raw)>=48 and len(raw)<=256 else None

def signed_report(data,key):
    return hmac.new(key,canonical(data),hashlib.sha256).hexdigest()

class HandoffRequest(BaseModel):
    acknowledgement:bool=False
    rationale:str=Field(min_length=12,max_length=1000)
class ReportRequest(BaseModel):
    payload:dict
    signature:str=Field(pattern=r'^[0-9a-f]{64}$')
class ReviewReport(BaseModel):
    decision:str=Field(pattern=r'^(accept_as_external_report|flag_for_investigation)$')
    rationale:str=Field(min_length=12,max_length=1500)

def register_worker_handoff(router,connection,now,actor,member,event,storage):
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS team_worker_handoffs(
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,request_id TEXT NOT NULL UNIQUE,
          challenge_hash TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,
          manifest_sha256 TEXT NOT NULL,created_by TEXT NOT NULL,
          created_at TEXT NOT NULL,status TEXT NOT NULL,
          report_sha256 TEXT,report_json TEXT,reported_at TEXT,
          reviewed_by TEXT,review_decision TEXT,review_rationale TEXT,reviewed_at TEXT);
          CREATE INDEX IF NOT EXISTS ix_team_worker_handoffs_ws ON team_worker_handoffs(workspace_id,created_at);
        ''')
    root=Path(storage).resolve()
    def get(db,wid,hid):
        r=db.execute('SELECT * FROM team_worker_handoffs WHERE workspace_id=? AND id=?',(wid,hid)).fetchone()
        if not r:raise HTTPException(404,'Handoff not found')
        return r
    def get_request(db,wid,rid):
        r=db.execute('SELECT * FROM team_execution_requests WHERE workspace_id=? AND id=?',(wid,rid)).fetchone()
        if not r:raise HTTPException(404,'Execution request not found')
        return r
    def artifact(db,request_row):
        f=db.execute('SELECT * FROM files WHERE id=? AND project_id=?',(request_row['artifact_id'],request_row['project_id'])).fetchone()
        if not f:raise HTTPException(409,'Artifact no longer exists')
        p=Path(f['storage_path']).resolve()
        if p.parent!=root or p.name!=f['id'] or not p.is_file():raise HTTPException(409,'Unsafe artifact path')
        if p.stat().st_size>2*1024*1024:raise HTTPException(413,'Artifact exceeds handoff limit')
        b=p.read_bytes()
        if sha(b)!=request_row['artifact_sha256'] or f['sha256']!=request_row['artifact_sha256']:
            raise HTTPException(409,'Source artifact does not match approved fingerprint')
        return b
    def present(r):
        d=dict(r)
        # Never include challenge material, worker secrets or full raw logs in list responses.
        for k in ('challenge_hash','report_json'):d.pop(k,None)
        d['actual_tests_executed_by_nesson']=False
        d['worker_isolation_attested']=False
        d['report_authenticated']=bool(r['report_sha256'])
        return d
    @router.get('/workspaces/{wid}/worker-handoffs/capabilities')
    def caps(wid:str,request:Request):
        with connection() as db:member(db,wid,actor(request))
        return {'handoff_enabled':bool(signing_secret()),'embedded_execution':False,
                'worker_isolation_attested':False,'report_state':'external_report_unverified',
                'details':'A valid MAC authenticates a configured worker key, not execution isolation.'}
    @router.post('/workspaces/{wid}/execution-requests/{rid}/handoff',status_code=201)
    def prepare_handoff(wid:str,rid:str,body:HandoffRequest,request:Request):
        who=actor(request)
        if not body.acknowledgement:raise HTTPException(422,'Explicit acknowledgement required')
        if not signing_secret():raise HTTPException(503,'External worker verification key is not configured')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin')
            r=get_request(db,wid,rid)
            if r['status']!='awaiting_isolated_worker' or not r['manifest_json']:
                raise HTTPException(409,'Approved prepared manifest required')
            if db.execute('SELECT id FROM team_worker_handoffs WHERE request_id=?',(rid,)).fetchone():
                raise HTTPException(409,'Handoff already created')
            manifest=json.loads(r['manifest_json'])
            if sha(canonical(manifest))!=r['manifest_sha256']:
                raise HTTPException(409,'Manifest fingerprint invalid')
            if manifest.get('artifact_sha256')!=r['artifact_sha256'] or manifest.get('execution_allowed') is not False:
                raise HTTPException(409,'Unsupported manifest')
            raw=artifact(db,r)
            # Operator handoff is explicit: NESSON never automatically sends files to a network service.
            challenge=secrets.token_urlsafe(32)
            hid=uuid.uuid4().hex
            db.execute('''INSERT INTO team_worker_handoffs
              (id,workspace_id,request_id,challenge_hash,artifact_sha256,manifest_sha256,created_by,created_at,status)
              VALUES(?,?,?,?,?,?,?,?,?)''',
              (hid,wid,rid,sha(challenge.encode()),r['artifact_sha256'],r['manifest_sha256'],who['id'],now(),'awaiting_external_worker'))
            event(db,wid,who,'worker_handoff_created',hid,{'request_id':rid,'sha256':r['artifact_sha256']})
        # Challenge and ZIP bytes are returned once only to an authenticated workspace admin.
        # Do not expose this response in logs, shared browser history or screenshots.
        return {'handoff_id':hid,'challenge':challenge,'request_id':rid,
                'manifest':manifest,'manifest_sha256':r['manifest_sha256'],
                'artifact_sha256':r['artifact_sha256'], 'artifact_zip_base64':base64.b64encode(raw).decode(),
                'status':'awaiting_external_worker','actual_tests_executed':False,
                'warning':'Transport only to a separately secured and operator-verified isolated worker; no isolation is established by this handoff.'}
    @router.get('/workspaces/{wid}/worker-handoffs')
    def list_handoffs(wid:str,request:Request):
        with connection() as db:
            member(db,wid,actor(request))
            return [present(r) for r in db.execute('SELECT * FROM team_worker_handoffs WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]
    @router.get('/workspaces/{wid}/worker-handoffs/{hid}')
    def detail(wid:str,hid:str,request:Request):
        with connection() as db:
            member(db,wid,actor(request));r=get(db,wid,hid)
            d=present(r)
            if r['report_json']:
                report=json.loads(r['report_json'])
                d['external_report']={k:v for k,v in report.items() if k!='challenge'}
            return d
    @router.post('/workspaces/{wid}/worker-handoffs/{hid}/report')
    def receive_report(wid:str,hid:str,body:ReportRequest,request:Request):
        who=actor(request)
        key=signing_secret()
        if not key:raise HTTPException(503,'External worker key is not configured')
        payload=body.payload
        data=canonical(payload)
        if len(data)>MAX_REPORT:raise HTTPException(413,'Report exceeds maximum size')
        if not hmac.compare_digest(signed_report(payload,key),body.signature):
            raise HTTPException(403,'Invalid external report authenticator')
        allowed={'schema','handoff_id','request_id','challenge','manifest_sha256','artifact_sha256','selector',
                 'exit_code','stdout','stderr','elapsed_ms','worker_label'}
        if set(payload)!=allowed or payload.get('schema')!=1:
            raise HTTPException(422,'Invalid report schema')
        if not all(isinstance(payload.get(x),str) for x in ('handoff_id','request_id','challenge','manifest_sha256','artifact_sha256','selector','stdout','stderr','worker_label')):
            raise HTTPException(422,'Invalid report fields')
        if not isinstance(payload.get('exit_code'),int) or isinstance(payload['exit_code'],bool) or not -1<=payload['exit_code']<=255:
            raise HTTPException(422,'Invalid exit status')
        if not isinstance(payload.get('elapsed_ms'),int) or isinstance(payload['elapsed_ms'],bool) or not 0<=payload['elapsed_ms']<=120000:
            raise HTTPException(422,'Invalid duration')
        if len(payload['stdout'].encode())>MAX_LOG or len(payload['stderr'].encode())>MAX_LOG:
            raise HTTPException(413,'Execution output too large')
        if len(payload['worker_label'])>128 or not payload['worker_label']:
            raise HTTPException(422,'Invalid worker label')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin');r=get(db,wid,hid)
            if r['status']!='awaiting_external_worker':raise HTTPException(409,'Report already submitted')
            req=get_request(db,wid,r['request_id'])
            if payload['handoff_id']!=hid or payload['request_id']!=r['request_id'] or sha(payload['challenge'].encode())!=r['challenge_hash'] or payload['artifact_sha256']!=r['artifact_sha256'] or payload['manifest_sha256']!=r['manifest_sha256'] or payload['selector']!=req['selector']:
                raise HTTPException(409,'Report does not match the approved handoff')
            # Recheck the artifact, including after a long external job.
            artifact(db,req)
            fingerprint=sha(data)
            db.execute('''UPDATE team_worker_handoffs SET status='external_report_unverified',
                        report_sha256=?,report_json=?,reported_at=? WHERE id=?''',
                       (fingerprint,data.decode(),now(),hid))
            event(db,wid,who,'external_worker_report_received',hid,{'report_sha256':fingerprint,'independently_verified':False})
        return {'handoff_id':hid,'status':'external_report_unverified','report_sha256':fingerprint,
                'authenticated_sender':True,'actual_tests_executed_by_nesson':False,
                'worker_isolation_attested':False,'independently_verified':False}
    @router.post('/workspaces/{wid}/worker-handoffs/{hid}/review')
    def review_report(wid:str,hid:str,body:ReviewReport,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin');r=get(db,wid,hid)
            if r['status']!='external_report_unverified' or r['reviewed_at']:
                raise HTTPException(409,'External report not ready or already reviewed')
            if who['id']==r['created_by']:
                raise HTTPException(403,'Separate reviewer required')
            db.execute('''UPDATE team_worker_handoffs SET reviewed_by=?,review_decision=?,review_rationale=?,reviewed_at=?,status='external_report_reviewed' WHERE id=?''',
                       (who['id'],body.decision,body.rationale,now(),hid))
            event(db,wid,who,'external_worker_report_reviewed',hid,{'decision':body.decision,'independently_verified':False})
        return {'handoff_id':hid,'status':'external_report_reviewed','decision':body.decision,
                'independently_verified':False,'actual_tests_executed_by_nesson':False}
