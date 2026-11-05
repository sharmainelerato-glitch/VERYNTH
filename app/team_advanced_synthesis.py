"""Cross-feature advanced synthesis: evidence-bound human review, not autonomous execution.

Saved model outputs are *proposals*, simulations are *models*, and source hashes
are integrity checks, never an attestation of correctness or isolation.
"""
import json
import uuid
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from app.team_unified_intelligence import compute_brief, sha, canonical
from app.team_engineering_dossier import evidence_snapshot
from app.team_meta_model_lab import source_context

MAX_COMPARE = 12
MAX_ANSWER = 2400

class SaveSynthesis(BaseModel):
    investigation_id: str = Field(min_length=16, max_length=128)
    title: str = Field(min_length=6, max_length=150)
    assessment: str = Field(default='', max_length=3000)

def make_snapshot(db, wid, iid, storage):
    brief = compute_brief(db, wid, iid, storage)
    engineering = evidence_snapshot(db, wid, iid, storage)
    meta = []
    for row in db.execute('''SELECT id, model_ids_json, results_json, result_sha256,
                    evidence_sha256, created_at FROM team_meta_comparisons
                    WHERE workspace_id=? AND investigation_id=? ORDER BY created_at DESC, id DESC LIMIT ?''',
                    (wid, iid, MAX_COMPARE)):
        raw = row['results_json']
        intact = bool(raw and sha(raw.encode()) == row['result_sha256'])
        results=[]
        if intact:
            try:
                result_items=json.loads(raw)
                if not isinstance(result_items,list) or len(result_items)>2:
                    raise ValueError('Invalid comparisons')
                results=[{'model':str(x['model'])[:80], 'answer_excerpt':str(x['answer'])[:MAX_ANSWER],
                          'kind':'model_generated_not_independently_verified'} for x in result_items]
            except (ValueError,TypeError,KeyError):
                intact=False
                results=[]
        meta.append({'id':row['id'], 'models':json.loads(row['model_ids_json']),
          'result_hash':row['result_sha256'], 'integrity':'intact' if intact else 'changed_or_invalid',
          'evidence_sha256':row['evidence_sha256'], 'results':results,
          'created_at':row['created_at'], 'kind':'saved_meta_model_comparison_not_fact_check'})
    # Each comparison pins its own evidence, which may differ from the latest investigation.
    evidence_available=all(s['state']=='intact' for s in brief['sources'])
    try:
        _,meta_current=source_context(db,wid,iid,storage)
        meta_state='current'
    except HTTPException:
        meta_current=None
        meta_state='unavailable_or_changed'
    for item in meta:
        item['evidence_freshness'] = ('current' if meta_current and
              item['evidence_sha256']==meta_current else 'stale_or_unverifiable')
    sims=[{'id':s['id'],'kind':s['kind'],'status':s['status'],
           'input_sha256':s['input_sha256'],'output_sha256':s['output_sha256'],
           'outputs':s['outputs']} for s in engineering['saved_simulations'][:20]]
    risk=[]
    if not evidence_available:risk.append('One or more source files failed integrity checks.')
    if not meta:risk.append('No saved Meta model comparisons for this investigation.')
    if any(x['integrity']!='intact' for x in meta):risk.append('A saved model response has been altered.')
    if any(x['evidence_freshness']!='current' for x in meta):risk.append('At least one Meta response uses stale or unavailable evidence.')
    if not sims:risk.append('No project-level saved simulation is available.')
    risk.extend(brief['gaps'][:8])
    result={'version':1,'workspace_id':wid,'investigation_id':iid,'project_id':brief['project_id'],
      'question':brief['question'],'domain_signals':brief['domains'],
      'evidence_integrity':brief['integrity'],'brief_fingerprint':brief['fingerprint'],
      'engineering_fingerprint':engineering['fingerprint'],'meta_evidence_status':meta_state,
      'meta_comparisons':meta,'reality_twin_simulations':sims,
      'human_actions_required':risk,
      'verification':{'meta_responses':'not_independently_verified',
         'simulation_outputs':'computed_models_not_experimental_confirmation',
         'source_files':'sha256_integrity_only','afterlight':'on_demand_snapshot_freshness_check',
         'ai_council':'multiple_saved_model_perspectives_only_no_independent_agent_debate',
         'repository_tests':'not_independently_verified'},
      'autonomous_actions_executed':False,'new_model_calls':0,'new_simulations_run':0}
    result['fingerprint']=sha(canonical(result).encode())
    return result

def register_advanced_synthesis(router,connection,now,actor,member,event,storage):
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS team_advanced_syntheses (
          id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, investigation_id TEXT NOT NULL,
          title TEXT NOT NULL, assessment TEXT NOT NULL, snapshot_json TEXT NOT NULL,
          fingerprint TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS ix_team_advanced_workspace ON team_advanced_syntheses(workspace_id,created_at);''')

    @router.get('/workspaces/{wid}/advanced/preview/{iid}')
    def preview(wid:str,iid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return make_snapshot(db,wid,iid,storage)

    @router.post('/workspaces/{wid}/advanced/syntheses',status_code=201)
    def save(wid:str,body:SaveSynthesis,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            snap=make_snapshot(db,wid,body.investigation_id,storage)
            sid=uuid.uuid4().hex
            db.execute('INSERT INTO team_advanced_syntheses VALUES (?,?,?,?,?,?,?,?,?)',(
                sid,wid,body.investigation_id,body.title.strip(),body.assessment,
                canonical(snap),snap['fingerprint'],who['id'],now()))
            event(db,wid,who,'advanced_synthesis_saved',sid,{'investigation_id':body.investigation_id,
                                                              'fingerprint':snap['fingerprint']})
        return {'id':sid,'saved':True,'fingerprint':snap['fingerprint'],
                'models_called':0,'simulation_executed':False}

    @router.get('/workspaces/{wid}/advanced/syntheses')
    def listing(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT id,title,investigation_id,created_at,
                 fingerprint FROM team_advanced_syntheses WHERE workspace_id=?
                 ORDER BY created_at DESC,id DESC LIMIT 60''',(wid,))]

    @router.get('/workspaces/{wid}/advanced/syntheses/{sid}')
    def detail(wid:str,sid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            row=db.execute('SELECT * FROM team_advanced_syntheses WHERE workspace_id=? AND id=?',
                           (wid,sid)).fetchone()
            if not row:raise HTTPException(404,'Synthesis not found')
            snapshot=json.loads(row['snapshot_json'])
            if canonical(snapshot)!=row['snapshot_json'] or sha(canonical({k:v for k,v in snapshot.items() if k!='fingerprint'}).encode())!=row['fingerprint'] or snapshot.get('fingerprint')!=row['fingerprint']:
                raise HTTPException(409,'Saved synthesis has been modified')
            current=make_snapshot(db,wid,row['investigation_id'],storage)
            return {'id':sid,'title':row['title'],'assessment':row['assessment'],
                    'snapshot':snapshot,'saved_snapshot_intact':True,
                    'matches_current_evidence':current['fingerprint']==row['fingerprint'],
                    'current_fingerprint':current['fingerprint'],'created_at':row['created_at'],
                    'external_verification':False}
