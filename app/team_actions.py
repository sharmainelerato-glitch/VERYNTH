"""NESSON safe, evidence-bound workspace tool lifecycle.

Only built-in, non-code-executing parsers run in the app process. Arbitrary code,
repository tests, network tools and filesystem changes require an external
isolated provider, not implemented here. No fabricated logs or outcomes.
"""
import csv
import hashlib
import io
import json
import math
import sqlite3
import uuid
from pathlib import Path
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from app.team_domain_tools import DOMAIN_TOOLS, validate_parameters, run_domain_tool
from app.team_repo_tools import REPO_TOOLS, validate_repo_parameters, run_repo_tool

MAX_SOURCE = 2 * 1024 * 1024
TOOLS = {
    'file.sha256': {'description': 'Recompute the SHA-256 of a stored project file', 'risk': 'read_only'},
    'text.profile': {'description': 'Count UTF-8 text lines, words and characters', 'risk': 'read_only'},
    'json.validate': {'description': 'Parse JSON and summarize top-level structure', 'risk': 'read_only'},
    'csv.profile': {'description': 'Parse bounded CSV and report headers and column completeness', 'risk': 'read_only'},
    'csv.numeric_stats': {'description': 'Calculate bounded numeric descriptive statistics for a CSV column', 'risk': 'read_only'},
}

TOOLS.update(DOMAIN_TOOLS)
TOOLS.update(REPO_TOOLS)

class NewAction(BaseModel):
    project_id: str = Field(min_length=16,max_length=128)
    file_id: str = Field(min_length=16,max_length=128)
    tool: str = Field(min_length=3,max_length=80)
    parameters: dict = Field(default_factory=dict)
    reason: str = Field(min_length=12,max_length=2000)
    investigation_id: str|None = None

class Review(BaseModel):
    decision: str = Field(pattern='^(approve|reject)$')
    rationale: str = Field(min_length=12,max_length=2000)

class RunRequest(BaseModel):
    acknowledgement: bool = False

class LinkToPlan(BaseModel):
    plan_id: str = Field(min_length=16,max_length=128)
    step_id: str = Field(min_length=16,max_length=128)


def _run(tool,raw,params):
    if tool in DOMAIN_TOOLS:return run_domain_tool(tool,raw,params)
    if tool in REPO_TOOLS:return run_repo_tool(tool,raw,params)
    if tool=='file.sha256':
        if params:raise ValueError('This tool accepts no parameters')
        return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    try: text=raw.decode('utf-8-sig')
    except UnicodeDecodeError:raise ValueError('Source is not UTF-8 text')
    if tool=='text.profile':
        if params:raise ValueError('This tool accepts no parameters')
        return {'lines':len(text.splitlines()),'words':len(text.split()),'characters':len(text),'bytes':len(raw)}
    if tool=='json.validate':
        if params:raise ValueError('This tool accepts no parameters')
        try:obj=json.loads(text,parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Non-finite JSON number')))
        except (json.JSONDecodeError,ValueError) as e:raise ValueError('Invalid JSON: '+str(e)[:160])
        kind=('object' if isinstance(obj,dict) else 'array' if isinstance(obj,list) else type(obj).__name__)
        return {'valid_json':True,'top_level_type':kind,'top_level_length':len(obj) if isinstance(obj,(dict,list)) else None,'keys':list(obj)[:100] if isinstance(obj,dict) else None}
    if tool in ('csv.profile','csv.numeric_stats'):
        if any(k not in ('column',) for k in params):raise ValueError('Unknown parameter')
        try:
            rows=csv.reader(io.StringIO(text,newline=''),strict=True)
            header=next(rows)
        except (StopIteration,csv.Error):raise ValueError('Invalid or empty CSV')
        if not header or len(header)>100 or len(set(header))!=len(header) or any(not h.strip() for h in header):raise ValueError('CSV headers must be nonempty and unique (max 100)')
        counts=[0]*len(header);numbers=[];column=params.get('column')
        if tool=='csv.numeric_stats' and (not isinstance(column,str) or column not in header):raise ValueError('A valid column parameter is required')
        if tool=='csv.profile' and params:raise ValueError('CSV profile takes no parameters')
        index=header.index(column) if column is not None else None
        count=0
        try:
            for row in rows:
                count+=1
                if count>10000:raise ValueError('CSV row limit exceeded (10000)')
                if len(row)!=len(header):raise ValueError('CSV row width mismatch')
                for i,value in enumerate(row):
                    if value.strip():counts[i]+=1
                if index is not None and row[index].strip():
                    try:v=float(row[index])
                    except ValueError:raise ValueError('Selected column contains non-numeric values')
                    if not math.isfinite(v):raise ValueError('Selected column contains non-finite values')
                    numbers.append(v)
        except csv.Error:raise ValueError('Malformed CSV')
        if tool=='csv.profile':return {'rows':count,'columns':len(header),'headers':header,'nonempty_by_column':dict(zip(header,counts))}
        if not numbers:raise ValueError('No numeric observations in selected column')
        return {'column':column,'count':len(numbers),'missing':count-len(numbers),'sum':math.fsum(numbers),'mean':math.fsum(numbers)/len(numbers),'min':min(numbers),'max':max(numbers)}
    raise ValueError('Unsupported tool')


def register_team_actions(router,connection,now,actor,member,event,storage):
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS team_tool_actions(
            id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,project_id TEXT NOT NULL,
            investigation_id TEXT,file_id TEXT NOT NULL,tool TEXT NOT NULL,
            parameters_json TEXT NOT NULL,reason TEXT NOT NULL,source_sha256 TEXT NOT NULL,
            requested_by TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS team_tool_reviews(
            id TEXT PRIMARY KEY,action_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
            reviewer_id TEXT NOT NULL,decision TEXT NOT NULL,rationale TEXT NOT NULL,created_at TEXT NOT NULL,
            UNIQUE(action_id));
        CREATE TABLE IF NOT EXISTS team_tool_attempts(
            id TEXT PRIMARY KEY,action_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
            initiated_by TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,result_json TEXT,error TEXT,
            result_sha256 TEXT,created_at TEXT NOT NULL,completed_at TEXT,
            UNIQUE(action_id));
        CREATE TABLE IF NOT EXISTS team_tool_plan_links(
            id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,action_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,plan_id TEXT NOT NULL,step_id TEXT NOT NULL,
            source_sha256 TEXT NOT NULL,result_sha256 TEXT NOT NULL,
            linked_by TEXT NOT NULL,created_at TEXT NOT NULL,
            UNIQUE(action_id,step_id));
        CREATE INDEX IF NOT EXISTS ix_tool_plan_links_plan ON team_tool_plan_links(plan_id,step_id);
        CREATE INDEX IF NOT EXISTS ix_tool_actions_ws ON team_tool_actions(workspace_id,created_at);
        ''')
        # In-process parsers cannot survive a process restart. Preserve the original
        # attempt as interrupted; never invent success or silently retry it.
        db.execute("UPDATE team_tool_attempts SET status='interrupted',error='Server restarted before completion',completed_at=? WHERE status='running'",(now(),))
        db.execute("UPDATE team_tool_actions SET status='interrupted',updated_at=? WHERE status='running'",(now(),))


    def _get(db,wid,aid):
        item=db.execute('SELECT * FROM team_tool_actions WHERE workspace_id=? AND id=?',(wid,aid)).fetchone()
        if item is None:raise HTTPException(404,'Action not found')
        return item

    def _source(db,wid,pid,fid):
        if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,pid)).fetchone():
            raise HTTPException(404,'Shared project not found')
        file=db.execute('SELECT * FROM files WHERE id=? AND project_id=?',(fid,pid)).fetchone()
        if not file:raise HTTPException(404,'Shared source not found')
        return file

    def _bytes(file):
        path=Path(file['storage_path']).resolve()
        root=Path(storage).resolve()
        if path.parent!=root or path.name!=file['id']:raise HTTPException(409,'Stored path safety check failed')
        if not path.is_file():raise HTTPException(409,'Source is missing')
        if path.stat().st_size>MAX_SOURCE:raise HTTPException(413,'Interactive tool limit is 2 MiB')
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=file['sha256']:raise HTTPException(409,'Stored source integrity failed')
        return raw

    def _public(row):
        result=dict(row);result['parameters']=json.loads(result.pop('parameters_json'))
        return result

    @router.get('/tools/registry')
    def registry(request:Request):
        actor(request)
        return {'safe_readonly_tools': [{'id':k,**v,'available':True} for k,v in TOOLS.items()],
                'untrusted_code_execution':{'available':False,'reason':'Requires a separately isolated execution provider'},
                'automatic_file_changes':{'available':False,'reason':'Requires separate change approval and isolated verification'},
                'execution_provider_contract':{'version':'1','status':'not_connected','available':False,'security_boundary':'remote isolated worker required','supported_job_type':'repository_tests','requirements':['external filesystem and process isolation','explicit network policy','CPU/memory/time limits','artifact integrity','independent approval','signed result provenance'],'local_subprocess_fallback':False}}

    @router.post('/workspaces/{wid}/tool-actions',status_code=201)
    def propose(wid:str,body:NewAction,request:Request):
        who=actor(request)
        if body.tool not in TOOLS:raise HTTPException(422,'Tool unavailable')
        if len(json.dumps(body.parameters))>2000:raise HTTPException(422,'Parameters too large')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            file=_source(db,wid,body.project_id,body.file_id)
            if body.investigation_id:
                found=db.execute('SELECT 1 FROM team_investigations WHERE id=? AND workspace_id=? AND project_id=?',
                                  (body.investigation_id,wid,body.project_id)).fetchone()
                if not found:raise HTTPException(404,'Investigation not found in shared project')
            # Validate inputs before asking for review; no execution or file reading at proposal time.
            if body.tool in DOMAIN_TOOLS or body.tool in REPO_TOOLS:
                try:
                    if body.tool in REPO_TOOLS:validate_repo_parameters(body.tool,body.parameters)
                    else:validate_parameters(body.tool,body.parameters)
                except ValueError as exc:raise HTTPException(422,str(exc))
            elif body.tool=='csv.numeric_stats':
                if set(body.parameters)!={'column'} or not isinstance(body.parameters.get('column'),str) or not body.parameters['column'].strip() or len(body.parameters['column'])>150:
                    raise HTTPException(422,'Select exactly one CSV column')
            elif body.parameters:raise HTTPException(422,'Unknown tool parameters')
            aid=uuid.uuid4().hex;stamp=now()
            db.execute('INSERT INTO team_tool_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                 (aid,wid,body.project_id,body.investigation_id,body.file_id,body.tool,json.dumps(body.parameters,sort_keys=True),
                  body.reason.strip(),file['sha256'],who['id'],'proposed',stamp,stamp))
            event(db,wid,who,'tool_action_proposed',aid,{'tool':body.tool,'read_only':True})
        return {'id':aid,'status':'proposed','executed':False}

    @router.get('/workspaces/{wid}/tool-actions')
    def list_actions(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [_public(r) for r in db.execute('SELECT * FROM team_tool_actions WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]

    @router.get('/workspaces/{wid}/tool-actions/{aid}')
    def detail(wid:str,aid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            item=_get(db,wid,aid)
            review=db.execute('SELECT * FROM team_tool_reviews WHERE action_id=? AND workspace_id=?',(aid,wid)).fetchone()
            attempts=[dict(x) for x in db.execute('SELECT * FROM team_tool_attempts WHERE action_id=? AND workspace_id=?',(aid,wid))]
            for attempt in attempts:
                if attempt['result_json'] is not None:attempt['result']=json.loads(attempt.pop('result_json'))
            linked=[dict(x) for x in db.execute('SELECT * FROM team_tool_plan_links WHERE workspace_id=? AND action_id=? ORDER BY created_at',(wid,aid))]
            return {'action':_public(item),'review':dict(review) if review else None,'attempts':attempts,'linked_plan_steps':linked}

    @router.get('/workspaces/{wid}/tool-actions/{aid}/verify')
    def verify(wid:str,aid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            action=_get(db,wid,aid)
            attempts=[dict(x) for x in db.execute('SELECT * FROM team_tool_attempts WHERE action_id=? AND workspace_id=?',(aid,wid))]
            f=_source(db,wid,action['project_id'],action['file_id'])
        source_state='verified'
        try:_bytes(f)
        except HTTPException:source_state='unavailable_or_modified'
        checks=[]
        for a in attempts:
            if a['status']=='succeeded' and a['result_json']:
                digest=hashlib.sha256(a['result_json'].encode()).hexdigest()
                intact=digest==a['result_sha256']
            else:intact=None
            checks.append({'attempt_id':a['id'],'status':a['status'],'result_fingerprint_intact':intact,
                           'source_fingerprint_matches_approved':a['source_sha256']==action['source_sha256']})
        return {'action_id':aid,'source_state':source_state,'checks':checks,
                'limitations':'Hash checks detect stored content changes; they do not independently certify semantic correctness.'}

    @router.post('/workspaces/{wid}/tool-actions/{aid}/link-plan',status_code=201)
    def link_plan(wid:str,aid:str,body:LinkToPlan,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            action=_get(db,wid,aid)
            if action['status']!='succeeded' or not action['investigation_id']:
                raise HTTPException(409,'Only a successful investigation-linked tool result can be attached')
            attempt=db.execute('''SELECT * FROM team_tool_attempts WHERE workspace_id=? AND action_id=? AND status='succeeded' ''',(wid,aid)).fetchone()
            if not attempt or not attempt['result_json'] or not attempt['result_sha256']:
                raise HTTPException(409,'Verified result unavailable')
            actual_hash=hashlib.sha256(attempt['result_json'].encode()).hexdigest()
            if actual_hash!=attempt['result_sha256']:
                raise HTTPException(409,'Tool result integrity check failed')
            source=_source(db,wid,action['project_id'],action['file_id'])
            if source['sha256']!=action['source_sha256']:
                raise HTTPException(409,'Original source fingerprint changed')
            _bytes(source)
            plan=db.execute('''SELECT p.id FROM team_orchestration_plans p
              JOIN team_investigations i ON i.id=p.investigation_id AND i.workspace_id=p.workspace_id
              WHERE p.id=? AND p.workspace_id=? AND p.investigation_id=? AND i.project_id=?''',
              (body.plan_id,wid,action['investigation_id'],action['project_id'])).fetchone()
            if not plan:raise HTTPException(404,'Plan is not linked to this investigation and shared project')
            step=db.execute('SELECT id FROM team_orchestration_steps WHERE workspace_id=? AND plan_id=? AND id=?',
                            (wid,body.plan_id,body.step_id)).fetchone()
            if not step:raise HTTPException(404,'Step not found in plan')
            evidence=db.execute('SELECT 1 FROM team_investigation_sources WHERE investigation_id=? AND file_id=?',
                                (action['investigation_id'],action['file_id'])).fetchone()
            if not evidence:raise HTTPException(409,'Source must be part of the original investigation')
            lid=uuid.uuid4().hex;stamp=now()
            try:
                db.execute('INSERT INTO team_tool_plan_links VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (lid,wid,aid,attempt['id'],body.plan_id,body.step_id,action['source_sha256'],attempt['result_sha256'],who['id'],stamp))
            except sqlite3.IntegrityError:raise HTTPException(409,'Tool result already linked to this step')
            event(db,wid,who,'tool_result_linked_to_plan',aid,{'plan_id':body.plan_id,'step_id':body.step_id,'result_sha256':attempt['result_sha256']})
        return {'id':lid,'action_id':aid,'plan_id':body.plan_id,'step_id':body.step_id,
                'verified_result_sha256':attempt['result_sha256'],'step_completed':False,
                'limitations':'A linked tool result is supporting evidence, not an automatic step completion or approval'}

    @router.post('/workspaces/{wid}/tool-actions/{aid}/review')
    def review(wid:str,aid:str,body:Review,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin')
            item=_get(db,wid,aid)
            if item['status']!='proposed':raise HTTPException(409,'Action already reviewed')
            if item['requested_by']==who['id']:raise HTTPException(403,'The requester cannot review their own action')
            status='approved' if body.decision=='approve' else 'rejected';stamp=now()
            db.execute('INSERT INTO team_tool_reviews VALUES(?,?,?,?,?,?,?)',
                       (uuid.uuid4().hex,aid,wid,who['id'],body.decision,body.rationale.strip(),stamp))
            db.execute('UPDATE team_tool_actions SET status=?,updated_at=? WHERE id=?',(status,stamp,aid))
            event(db,wid,who,'tool_action_reviewed',aid,{'decision':body.decision})
        return {'id':aid,'status':status,'executed':False}

    @router.post('/workspaces/{wid}/tool-actions/{aid}/run')
    def run(wid:str,aid:str,body:RunRequest,request:Request):
        who=actor(request)
        if not body.acknowledgement:raise HTTPException(422,'Explicit execution acknowledgement required')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            action=_get(db,wid,aid)
            if action['status']!='approved':raise HTTPException(409,'Requires independent approval and no prior execution')
            file=_source(db,wid,action['project_id'],action['file_id'])
            if file['sha256']!=action['source_sha256']:
                raise HTTPException(409,'Source changed since approval; create a new action')
            raw=_bytes(file)  # Verify bytes before claiming a safe operation can run.
            attempt_id=uuid.uuid4().hex;stamp=now()
            db.execute('INSERT INTO team_tool_attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                     (attempt_id,aid,wid,who['id'],'nesson.safe_parser_v1','running',action['source_sha256'],None,None,None,stamp,None))
            db.execute('UPDATE team_tool_actions SET status=?,updated_at=? WHERE id=?',('running',stamp,aid))
            event(db,wid,who,'safe_tool_started',aid,{'tool':action['tool'],'attempt_id':attempt_id})
        # Synchronous bounded parser only. NOT a sandbox for arbitrary code.
        try:
            result=_run(action['tool'],raw,json.loads(action['parameters_json']))
            serialized=json.dumps(result,sort_keys=True,allow_nan=False)
            status='succeeded';error=None
        except (ValueError,OverflowError,UnicodeError,RecursionError) as exc:
            serialized=None;status='failed';error=str(exc)[:300]
        except Exception:
            # Persist a real failure without revealing internals or faking a result.
            serialized=None;status='failed';error='Unexpected safe-parser error; inspect server diagnostics'
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            stamp=now()
            digest=hashlib.sha256(serialized.encode()).hexdigest() if serialized is not None else None
            db.execute('UPDATE team_tool_attempts SET status=?,result_json=?,error=?,result_sha256=?,completed_at=? WHERE id=?',
                       (status,serialized,error,digest,stamp,attempt_id))
            db.execute('UPDATE team_tool_actions SET status=?,updated_at=? WHERE id=?',(status,stamp,aid))
            event(db,wid,who,'safe_tool_finished',aid,{'status':status,'attempt_id':attempt_id,'result_sha256':digest})
        return {'action_id':aid,'attempt_id':attempt_id,'status':status,'result':result if status=='succeeded' else None,
                'error':error,'result_sha256':digest,'provider':'nesson.safe_parser_v1','untrusted_code_executed':False}
