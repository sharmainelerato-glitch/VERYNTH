"""NESSON unified evidence brief. No implicit AI calls, code execution, or approvals.

All sources are bounded, workspace scoped, and fingerprinted. AI model reviews are
identified as model-generated rather than verified tool outcomes.
"""
import hashlib
import json
import re
import uuid
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from app.team_orchestration import classify

MAX_SOURCES=30
MAX_TOOLS=50
MAX_REVIEWS=20
MAX_REPORT=90000

class BriefInput(BaseModel):
    investigation_id:str=Field(min_length=16,max_length=128)
    title:str=Field(min_length=5,max_length=150)
    interpretation:str=Field(default='',max_length=4000)
    limitations:str=Field(default='',max_length=3000)


def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))
def escape_md(text):
    return str(text).replace('\\','\\\\').replace('`','\\`').replace('|','\\|').replace('<','&lt;').replace('>','&gt;')

def compute_brief(db,wid,iid,storage):
    inv=db.execute('SELECT * FROM team_investigations WHERE workspace_id=? AND id=?',(wid,iid)).fetchone()
    if not inv:raise HTTPException(404,'Investigation not found')
    project=db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,inv['project_id'])).fetchone()
    if not project:raise HTTPException(409,'Investigation project is no longer linked to workspace')
    sources=[];root=Path(storage).resolve()
    rows=db.execute('''SELECT s.file_id,s.sha256 AS pinned_hash,f.filename,f.sha256 AS stored_hash,
        f.storage_path,f.extract_status,f.extracted_text FROM team_investigation_sources s
        LEFT JOIN files f ON f.id=s.file_id AND f.project_id=? WHERE s.investigation_id=?
        ORDER BY s.file_id LIMIT ?''',(inv['project_id'],iid,MAX_SOURCES+1)).fetchall()
    if len(rows)>MAX_SOURCES:raise HTTPException(409,'Source inventory exceeds report bound')
    for f in rows:
        state='missing' if f['filename'] is None else 'intact'
        if state=='intact':
            path=Path(f['storage_path']).resolve()
            if path.parent!=root or path.name!=f['file_id'] or not path.is_file():state='missing_or_unsafe'
            elif path.stat().st_size>15*1024*1024:state='unverifiable_size'
            elif sha(path.read_bytes())!=f['pinned_hash'] or f['stored_hash']!=f['pinned_hash']:state='changed'
        extracted=bool((f['extracted_text'] or '').strip()) if f['filename'] else False
        sources.append({'id':f['file_id'],'filename':f['filename'] or '[missing]',
          'pinned_sha256':f['pinned_hash'],'state':state,'extraction_status':f['extract_status'] if f['filename'] else 'missing',
          'has_extracted_text':extracted,'excerpt':(f['extracted_text'] or '')[:400] if state=='intact' else ''})
    reviews=[dict(x) for x in db.execute('''SELECT id,answer,model,evidence_sha256,created_at FROM team_investigation_reviews
        WHERE workspace_id=? AND investigation_id=? ORDER BY created_at DESC LIMIT ?''',(wid,iid,MAX_REVIEWS))]
    for x in reviews:
        x['provenance']='model_generated_not_independently_verified'
        x['answer']=x['answer'][:6000]
    actions=[dict(x) for x in db.execute('''SELECT a.id,a.tool,a.status,a.file_id,a.source_sha256,
        t.status AS attempt_status,t.result_sha256,t.result_json,t.source_sha256 AS attempt_source_sha
        FROM team_tool_actions a LEFT JOIN team_tool_attempts t ON t.action_id=a.id AND t.workspace_id=a.workspace_id
        WHERE a.workspace_id=? AND a.investigation_id=? AND a.project_id=?
        ORDER BY a.created_at DESC LIMIT ?''',(wid,iid,inv['project_id'],MAX_TOOLS))]
    by_source={f['id']:f for f in sources}
    for a in actions:
        raw=a.pop('result_json')
        source=by_source.get(a['file_id'])
        valid=bool(a['status']=='succeeded' and a['attempt_status']=='succeeded' and raw is not None and
                   a['result_sha256'] and sha(raw.encode())==a['result_sha256'] and
                   source and source['state']=='intact' and source['pinned_sha256']==a['source_sha256'] and
                   a['attempt_source_sha']==a['source_sha256'])
        a['integrity']='intact' if valid else 'unverified_or_unavailable'
        a['execution_kind']='bounded_read_only_tool_not_repository_test'
        if valid:
            try:a['result']=json.loads(raw)
            except (ValueError,TypeError):a['integrity']='unverified_or_unavailable';a['result']=None
        else:a['result']=None
    plans=[dict(x) for x in db.execute('''SELECT id,goal,status,domains_json,created_at FROM team_orchestration_plans
        WHERE workspace_id=? AND investigation_id=? ORDER BY created_at DESC LIMIT 10''',(wid,iid))]
    for p in plans:
        p['domains']=json.loads(p.pop('domains_json'))
        p['steps']=[{'title':s['title'],'status':s['status'],'capability':s['capability']}
                    for s in db.execute('SELECT title,status,capability FROM team_orchestration_steps WHERE plan_id=? AND workspace_id=? ORDER BY position LIMIT 30',(p['id'],wid))]
    approvals=[dict(x) for x in db.execute('''SELECT id,action,status,created_at FROM team_approval_requests
        WHERE workspace_id=? AND investigation_id=? ORDER BY created_at DESC LIMIT 30''',(wid,iid))]
    # Content is heuristic context only; never infer the true discipline from filename alone.
    text=inv['question']+' '+' '.join(s['filename']+' '+s['excerpt'] for s in sources if s['state']=='intact')
    domains=classify(text)
    integrity={'sources_total':len(sources),'sources_intact':sum(s['state']=='intact' for s in sources),
      'sources_extracted':sum(s['state']=='intact' and s['has_extracted_text'] for s in sources),
      'tool_results_verified':sum(a['integrity']=='intact' for a in actions),'tool_results_unverified':sum(a['integrity']!='intact' for a in actions),
      'model_reviews':len(reviews),'runtime_repository_tests_verified':0}
    gaps=[]
    if not sources:gaps.append('No source files were linked to this investigation.')
    if any(s['state']!='intact' for s in sources):gaps.append('Some source files are missing, changed or cannot be integrity-checked.')
    if sources and not integrity['sources_extracted']:gaps.append('No extracted source text is available to ground the model review.')
    if any(a['integrity']!='intact' for a in actions):gaps.append('Some tool outcomes lack intact result and source provenance.')
    if not reviews:gaps.append('No saved Ness model review is associated with this investigation.')
    if not integrity['tool_results_verified']:gaps.append('No verified read-only tool results are linked to this investigation.')
    gaps.append('Repository runtime test execution is not established by this brief.')
    contents={'investigation_id':iid,'workspace_id':wid,'project_id':inv['project_id'],
        'question':inv['question'],'domains':domains,'sources':sources,'ness_reviews':reviews,
        'tool_actions':actions,'plans':plans,'approvals':approvals,'integrity':integrity,'gaps':gaps,
        'verification_scope':'hashes_and_saved_records_only','automatic_approval':False,'code_executed':False}
    contents['fingerprint']=sha(canonical(contents).encode())
    return contents


def markdown_report(snapshot,title,interpretation='',limitations=''):
    doc=[f'# {escape_md(title)}','',f'Investigation: `{snapshot["investigation_id"]}`',
        f'Fingerprint: `{snapshot["fingerprint"]}`','', '## Question',escape_md(snapshot['question']),'',
        '## Context suggestions (heuristic)',', '.join(escape_md(d['domain']) for d in snapshot['domains']),'',
        '## Evidence and integrity']
    for s in snapshot['sources']:
        doc.append(f'- `{escape_md(s["id"])}` {escape_md(s["filename"])} — {s["state"]}; extracted text: {s["has_extracted_text"]}; SHA-256: `{s["pinned_sha256"]}`')
    doc.extend(['','## Recorded tool outcomes (read-only, not code tests)'])
    if not snapshot['tool_actions']:doc.append('No recorded actions.')
    for a in snapshot['tool_actions']:
        doc.append(f'- {escape_md(a["tool"])} — {a["integrity"]}; action `{a["id"]}`; result fingerprint `{a["result_sha256"] or "none"}`')
        if a['integrity']=='intact':doc.append('  - Output: `'+escape_md(canonical(a['result'])[:1800])+'`')
    doc.extend(['','## Saved Ness AI reviews (model-generated, not independently verified)'])
    if not snapshot['ness_reviews']:doc.append('No saved model reviews.')
    for r in snapshot['ness_reviews']:
        doc.extend([f'### Review `{r["id"]}` · model {escape_md(r["model"])}',escape_md(r['answer']),''])
    doc.extend(['## Recorded plans and human approvals'])
    for p in snapshot['plans']:
        doc.append(f'- Plan `{p["id"]}`: {escape_md(p["status"])}; '+', '.join(escape_md(s['title'])+': '+escape_md(s['status']) for s in p['steps']))
    for a in snapshot['approvals']:doc.append(f'- Approval `{a["id"]}`: {escape_md(a["status"])} — {escape_md(a["action"])}')
    doc.extend(['','## Analyst interpretation (human-provided)',escape_md(interpretation) if interpretation else 'Not provided.','',
                '## Remaining limitations',escape_md(limitations) if limitations else 'No additional human limitations supplied.'])
    doc.extend('- '+escape_md(x) for x in snapshot['gaps'])
    doc.extend(['','**Verification disclaimer:** This is a saved-evidence summary, not proof of scientific correctness, autonomous agent execution, isolated repository test runs, or third-party certification.'])
    result='\n'.join(doc)
    if len(result)>MAX_REPORT:raise HTTPException(413,'Report exceeds export bound')
    return result


def register_unified_intelligence(router,connection,now,actor,member,event,storage):
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS team_unified_briefs(
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,investigation_id TEXT NOT NULL,
          project_id TEXT NOT NULL,title TEXT NOT NULL,snapshot_json TEXT NOT NULL,
          fingerprint TEXT NOT NULL,report_markdown TEXT NOT NULL,created_by TEXT NOT NULL,
          created_at TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS ix_unified_wid ON team_unified_briefs(workspace_id,created_at);''')

    @router.get('/workspaces/{wid}/unified/investigations/{iid}/preview')
    def preview(wid:str,iid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return compute_brief(db,wid,iid,storage)

    @router.post('/workspaces/{wid}/unified/briefs',status_code=201)
    def create(wid:str,body:BriefInput,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            snap=compute_brief(db,wid,body.investigation_id,storage)
            title=body.title.strip()
            if len(title)<5:raise HTTPException(422,'Report title too short')
            report=markdown_report(snap,title,body.interpretation,body.limitations)
            bid=uuid.uuid4().hex
            db.execute('INSERT INTO team_unified_briefs VALUES(?,?,?,?,?,?,?,?,?,?)',
                (bid,wid,body.investigation_id,snap['project_id'],title,canonical(snap),snap['fingerprint'],report,who['id'],now()))
            event(db,wid,who,'unified_brief_saved',bid,{'investigation_id':body.investigation_id,'fingerprint':snap['fingerprint']})
        return {'id':bid,'saved':True,'fingerprint':snap['fingerprint'],'model_invoked':False,'executed':False}

    @router.get('/workspaces/{wid}/unified/briefs')
    def listing(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('SELECT id,investigation_id,title,fingerprint,created_by,created_at FROM team_unified_briefs WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]

    def get(db,wid,bid):
        row=db.execute('SELECT * FROM team_unified_briefs WHERE workspace_id=? AND id=?',(wid,bid)).fetchone()
        if not row:raise HTTPException(404,'Saved brief not found')
        return row

    @router.get('/workspaces/{wid}/unified/briefs/{bid}')
    def detail(wid:str,bid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            b=get(db,wid,bid)
            saved=json.loads(b['snapshot_json'])
            actual=sha(canonical({k:v for k,v in saved.items() if k!='fingerprint'}).encode())
            intact=actual==b['fingerprint']==saved['fingerprint']
            return {'id':bid,'title':b['title'],'snapshot':saved,'snapshot_integrity':intact,
                    'snapshot_is_historical':True,'created_at':b['created_at']}

    @router.get('/workspaces/{wid}/unified/briefs/{bid}/freshness')
    def freshness(wid:str,bid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            b=get(db,wid,bid)
            old=json.loads(b['snapshot_json'])
            fresh=compute_brief(db,wid,b['investigation_id'],storage)
            return {'id':bid,'matches_current_records':old['fingerprint']==fresh['fingerprint'],
                    'saved_fingerprint':old['fingerprint'],'current_fingerprint':fresh['fingerprint'],
                    'historical_snapshot_preserved':True,'current_integrity':fresh['integrity']}

    @router.get('/workspaces/{wid}/unified/briefs/{bid}/export')
    def export(wid:str,bid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            b=get(db,wid,bid)
            saved=json.loads(b['snapshot_json'])
            actual=sha(canonical({k:v for k,v in saved.items() if k!='fingerprint'}).encode())
            if actual!=b['fingerprint'] or saved['fingerprint']!=b['fingerprint']:
                raise HTTPException(409,'Snapshot integrity failed')
            return PlainTextResponse(b['report_markdown'],headers={'Content-Disposition':'attachment; filename="nesson-investigation-brief.md"',
              'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})
