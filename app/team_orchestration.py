"""NESSON workspace-scoped, evidence-backed orchestration foundation.

Plans are deterministic and capability-limited. No AI reasoning or execution is claimed.
Only validated evidence results advance verification steps.
"""
import hashlib
import json
import re
import uuid
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field

CAPABILITIES = {
  'evidence.review': {'domains':['general','science','finance','security','software','engineering','data','business'], 'mode':'read_only', 'available':True},
  'analysis.math': {'domains':['mathematics','finance','science','engineering','data'], 'mode':'requires_validated_inputs', 'available':False},
  'simulation.saved': {'domains':['engineering','software','science'], 'mode':'requires_explicit_scenario', 'available':False},
  'verification.sources': {'domains':['general','science','finance','security','software','engineering','data','business'], 'mode':'read_only', 'available':True},
  'execution.isolated': {'domains':['software','security','data'], 'mode':'sandbox_required', 'available':False},
  'actions.modify': {'domains':['software','finance','business','engineering'], 'mode':'human_approval_and_execution_provider_required', 'available':False},
}
DOMAINS={
 'finance':('invoice','cash flow','balance sheet','finance','budget','profit','revenue','accounting'),
 'science':('research','hypothesis','experimental','scientific','paper','methodology','clinical'),
 'security':('vulnerability','malware','cybersecurity','incident','phishing','threat','security'),
 'software':('repository','debug','python','test failure','failing tests','source code','software','commit'),
 'engineering':('robot','actuator','thermal','sensor','mechanical','battery','engineering'),
 'mathematics':('integral','equation','algebra','mathematics','calculus','derive'),
 'data':('dataset','dataframe','statistics','csv','spreadsheet','regression'),
 'business':('operations','strategy','customers','sales','workflow','business')
}

class PlanRequest(BaseModel):
 investigation_id:str=Field(min_length=16,max_length=128)
 goal:str|None=Field(default=None,max_length=1500)
class StepRecord(BaseModel):
 outcome:str=Field(pattern='^(completed|blocked|failed)$')
 rationale:str=Field(min_length=8,max_length=3000)
 evidence_file_ids:list[str]=Field(default_factory=list,max_length=15)


def classify(text):
 t=text.lower()
 scores={name:sum(bool(re.search(r'(?<![\w])'+re.escape(word)+r'(?![\w])',t)) for word in words) for name,words in DOMAINS.items()}
 ranked=sorted(scores, key=lambda n:(-scores[n],list(DOMAINS).index(n)))
 return [{'domain':d,'matched_terms':scores[d]} for d in ranked if scores[d]>0][:3] or [{'domain':'general','matched_terms':0}]

def build_steps(domains,has_sources):
 primary=domains[0]['domain']
 steps=[('Understand context','evidence.review',[], 'ready', 'Review investigation question and extractable source references.'),
        ('Verify source coverage','verification.sources',[0], 'ready' if has_sources else 'needs_evidence','Check source availability and extraction state; gaps must be disclosed.')]
 if primary in ('finance','mathematics','data'):
  steps.append(('Validate numerical inputs','analysis.math',[1],'needs_inputs','Prepare explicit data and calculation assumptions; no computation has been executed.'))
 elif primary in ('engineering','science'):
  steps.append(('Prepare modeled scenario','simulation.saved',[1],'needs_inputs','Identify scenario inputs and uncertainty; no simulation has been run.'))
 elif primary in ('software','security'):
  steps.append(('Plan isolated verification','execution.isolated',[1],'unavailable','Requires a configured isolated execution provider and authorization; no code executed.'))
 else:
  steps.append(('Synthesize traceable findings','evidence.review',[1],'ready','Review evidence and limitations.'))
 steps.append(('Human review and decision','verification.sources',[2], 'waiting_for_dependencies','Evaluate actual recorded findings and determine next authorized action.'))
 return [{'position':i,'title':title,'capability':cap,'dependencies':deps,'availability':availability,'instructions':instructions} for i,(title,cap,deps,availability,instructions) in enumerate(steps)]

def register_orchestration(router,connection,now,actor,member,event):
 with connection() as db:
  db.executescript("""
   CREATE TABLE IF NOT EXISTS team_orchestration_plans(
      id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,investigation_id TEXT NOT NULL,
      goal TEXT NOT NULL,domains_json TEXT NOT NULL,source_fingerprint TEXT NOT NULL,
      created_by TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS team_orchestration_steps(
      id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,workspace_id TEXT NOT NULL,
      position INTEGER NOT NULL,title TEXT NOT NULL,capability TEXT NOT NULL,
      dependencies_json TEXT NOT NULL,availability TEXT NOT NULL,instructions TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',outcome_note TEXT,created_at TEXT NOT NULL,updated_at TEXT NOT NULL,
      UNIQUE(plan_id,position));
   CREATE TABLE IF NOT EXISTS team_orchestration_evidence(
      step_id TEXT NOT NULL,file_id TEXT NOT NULL,sha256 TEXT NOT NULL,
      PRIMARY KEY(step_id,file_id));
   CREATE TABLE IF NOT EXISTS team_orchestration_events(
      id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,plan_id TEXT NOT NULL,step_id TEXT,
      actor_id TEXT NOT NULL,event_type TEXT NOT NULL,detail_json TEXT NOT NULL,created_at TEXT NOT NULL);
   CREATE INDEX IF NOT EXISTS ix_orch_plans_workspace ON team_orchestration_plans(workspace_id,created_at);
   CREATE INDEX IF NOT EXISTS ix_orch_steps_plan ON team_orchestration_steps(plan_id,position);
  """)

 def log(db,wid,who,pid,sid,etype,detail):
  db.execute('INSERT INTO team_orchestration_events VALUES(?,?,?,?,?,?,?,?)',
      (uuid.uuid4().hex,wid,pid,sid,who['id'],etype,json.dumps(detail,sort_keys=True),now()))
  event(db,wid,who,'orchestration_'+etype,pid,{'step_id':sid})

 def getplan(db,wid,pid):
  p=db.execute('SELECT * FROM team_orchestration_plans WHERE workspace_id=? AND id=?',(wid,pid)).fetchone()
  if not p:raise HTTPException(404,'Plan not found')
  return p

 def steps_for(db,wid,pid):
  rows=[dict(x) for x in db.execute('SELECT * FROM team_orchestration_steps WHERE workspace_id=? AND plan_id=? ORDER BY position',(wid,pid))]
  for r in rows:
   r['dependencies']=json.loads(r.pop('dependencies_json'))
   r['evidence']=[dict(x) for x in db.execute('SELECT file_id,sha256 FROM team_orchestration_evidence WHERE step_id=?',(r['id'],))]
  return rows

 @router.get('/orchestration/capabilities')
 def capabilities(request:Request):
  actor(request)
  return [{'id':k,**v,'automated_execution_available':False} for k,v in CAPABILITIES.items()]

 @router.post('/workspaces/{wid}/orchestration/plans',status_code=201)
 def create(wid:str,body:PlanRequest,request:Request):
  who=actor(request)
  with connection() as db:
   db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
   investigation=db.execute('SELECT * FROM team_investigations WHERE workspace_id=? AND id=?',(wid,body.investigation_id)).fetchone()
   if not investigation:raise HTTPException(404,'Investigation not found')
   evidence=[dict(r) for r in db.execute("""SELECT f.id,f.filename,f.sha256,f.extracted_text,f.extract_status
     FROM team_investigation_sources s JOIN files f ON f.id=s.file_id AND f.project_id=?
     WHERE s.investigation_id=? ORDER BY f.id""",(investigation['project_id'],body.investigation_id))]
   goal=(body.goal or investigation['question']).strip()
   if len(goal)<10:raise HTTPException(422,'Goal too short')
   # Metadata and EXTRACTED text only. Unknown binary contents are not treated as read.
   domains=classify(goal+' '+' '.join(e['filename']+' '+(e['extracted_text'] or '')[:1000] for e in evidence))
   src_context=[{'id':e['id'],'sha256':e['sha256'],'extract_status':e['extract_status']} for e in evidence]
   fingerprint=hashlib.sha256(json.dumps({'goal':goal,'sources':src_context},sort_keys=True).encode()).hexdigest()
   planid=uuid.uuid4().hex;stamp=now()
   db.execute('INSERT INTO team_orchestration_plans VALUES(?,?,?,?,?,?,?,?,?,?)',
     (planid,wid,body.investigation_id,goal,json.dumps(domains),fingerprint,who['id'],'open',stamp,stamp))
   proposed=build_steps(domains,bool(evidence))
   for s in proposed:
    db.execute('INSERT INTO team_orchestration_steps VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
     (uuid.uuid4().hex,planid,wid,s['position'],s['title'],s['capability'],json.dumps(s['dependencies']),s['availability'],s['instructions'],'pending',None,stamp,stamp))
   log(db,wid,who,planid,None,'plan_created',{'domains':domains,'steps':len(proposed),'executed':False})
  return {'id':planid,'domains':domains,'steps':len(proposed),'executed':False,'status':'open'}

 @router.get('/workspaces/{wid}/orchestration/plans')
 def list_plans(wid:str,request:Request):
  who=actor(request)
  with connection() as db:
   member(db,wid,who)
   return [{**dict(r),'domains':json.loads(r['domains_json'])} for r in db.execute('SELECT * FROM team_orchestration_plans WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]

 @router.get('/workspaces/{wid}/orchestration/plans/{pid}')
 def detail(wid:str,pid:str,request:Request):
  who=actor(request)
  with connection() as db:
   member(db,wid,who)
   p=getplan(db,wid,pid)
   return {'plan':{**dict(p),'domains':json.loads(p['domains_json'])},'steps':steps_for(db,wid,pid),
           'activity':[dict(x) for x in db.execute('SELECT * FROM team_orchestration_events WHERE workspace_id=? AND plan_id=? ORDER BY created_at',(wid,pid))]}

 @router.post('/workspaces/{wid}/orchestration/plans/{pid}/steps/{sid}/record')
 def record_step(wid:str,pid:str,sid:str,body:StepRecord,request:Request):
  who=actor(request)
  if len(set(body.evidence_file_ids))!=len(body.evidence_file_ids):raise HTTPException(422,'Duplicate evidence IDs')
  with connection() as db:
   db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
   plan=getplan(db,wid,pid)
   step=db.execute('SELECT * FROM team_orchestration_steps WHERE plan_id=? AND workspace_id=? AND id=?',(pid,wid,sid)).fetchone()
   if not step:raise HTTPException(404,'Step not found')
   if step['status']!='pending':raise HTTPException(409,'Step already recorded')
   if body.outcome=='completed':
    if not CAPABILITIES[step['capability']]['available'] or step['availability'] in ('unavailable','needs_inputs'):
     raise HTTPException(409,'Capability not executed or required inputs unavailable')
    earlier={x['position']:x for x in db.execute('SELECT position,status FROM team_orchestration_steps WHERE plan_id=?',(pid,))}
    deps=json.loads(step['dependencies_json'])
    if any(earlier[d]['status']!='completed' for d in deps):raise HTTPException(409,'Dependencies not yet completed')
    if not body.evidence_file_ids:raise HTTPException(422,'Completion requires at least one real saved evidence file')
   project=db.execute('SELECT project_id FROM team_investigations WHERE workspace_id=? AND id=?',(wid,plan['investigation_id'])).fetchone()['project_id']
   for fid in body.evidence_file_ids:
    f=db.execute('SELECT sha256 FROM files WHERE project_id=? AND id=?',(project,fid)).fetchone()
    if not f:raise HTTPException(404,'Evidence outside linked shared project')
    linked=db.execute('SELECT 1 FROM team_investigation_sources WHERE investigation_id=? AND file_id=?',(plan['investigation_id'],fid)).fetchone()
    if not linked:raise HTTPException(409,'Evidence must be linked to this investigation')
    db.execute('INSERT INTO team_orchestration_evidence VALUES(?,?,?)',(sid,fid,f['sha256']))
   db.execute('UPDATE team_orchestration_steps SET status=?,outcome_note=?,updated_at=? WHERE id=?',
     (body.outcome,body.rationale.strip(),now(),sid))
   log(db,wid,who,pid,sid,'step_recorded',{'outcome':body.outcome,'evidence_count':len(body.evidence_file_ids),
        'execution_performed':False,'evidence_is_human_attested':True})
  return {'id':sid,'status':body.outcome,'execution_performed':False,'evidence_is_human_attested':True}
