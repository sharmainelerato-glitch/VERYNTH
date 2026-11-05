"""Evidence-bound human collaboration around a saved NESSON investigation brief.

No model calls, automatic authorizations or claims of runtime testing.
"""
import json
import uuid
from fastapi import HTTPException, Request
from pydantic import BaseModel, Field
from app.team_unified_intelligence import compute_brief, sha, canonical

class BriefComment(BaseModel):
    body: str = Field(min_length=5,max_length=3000)
    source_file_id: str | None = Field(default=None,max_length=128)

class BriefFollowup(BaseModel):
    title: str = Field(min_length=6,max_length=180)
    description: str = Field(min_length=10,max_length=2000)
    priority: str = 'normal'
    assignee_id: str | None = Field(default=None,max_length=128)

class ReviewDecision(BaseModel):
    decision: str
    rationale: str = Field(min_length=12,max_length=2500)


def register_brief_collaboration(router, connection, now, actor, member, event, storage):
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS team_brief_comments (
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,brief_id TEXT NOT NULL,
          investigation_id TEXT NOT NULL,actor_id TEXT NOT NULL,body TEXT NOT NULL,
          source_file_id TEXT,source_sha256 TEXT,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS team_brief_followups (
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,brief_id TEXT NOT NULL,
          task_id TEXT NOT NULL,created_by TEXT NOT NULL,created_at TEXT NOT NULL,
          UNIQUE(workspace_id,task_id));
        CREATE TABLE IF NOT EXISTS team_brief_reviews (
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,brief_id TEXT NOT NULL,
          reviewer_id TEXT NOT NULL,decision TEXT NOT NULL,rationale TEXT NOT NULL,
          snapshot_fingerprint TEXT NOT NULL,created_at TEXT NOT NULL,
          UNIQUE(workspace_id,brief_id,reviewer_id));
        CREATE INDEX IF NOT EXISTS idx_team_brief_comments ON team_brief_comments(workspace_id,brief_id,created_at);
        CREATE INDEX IF NOT EXISTS idx_team_brief_followups ON team_brief_followups(workspace_id,brief_id);
        CREATE INDEX IF NOT EXISTS idx_team_brief_reviews ON team_brief_reviews(workspace_id,brief_id);
        ''')

    def brief(db,wid,bid):
        row=db.execute('SELECT * FROM team_unified_briefs WHERE id=? AND workspace_id=?',(bid,wid)).fetchone()
        if not row:raise HTTPException(404,'Brief not found')
        if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,row['project_id'])).fetchone():
            raise HTTPException(409,'Brief source project is no longer shared')
        snap=json.loads(row['snapshot_json'])
        if sha(canonical({k:v for k,v in snap.items() if k!='fingerprint'}).encode()) != row['fingerprint'] or snap.get('fingerprint')!=row['fingerprint']:
            raise HTTPException(409,'Saved brief integrity failed')
        return row,snap

    def aggregate(db,wid,bid,row,snap):
        comments=[dict(x) for x in db.execute('''SELECT id,actor_id,body,source_file_id,source_sha256,created_at
              FROM team_brief_comments WHERE workspace_id=? AND brief_id=? ORDER BY created_at,id LIMIT 150''',(wid,bid))]
        followups=[dict(x) for x in db.execute('''SELECT f.id,f.task_id,t.title,t.description,t.priority,t.status,t.project_id,
              a.user_id AS assigned_to,f.created_by,f.created_at
              FROM team_brief_followups f JOIN collab_tasks t ON t.id=f.task_id AND t.workspace_id=f.workspace_id
              LEFT JOIN team_task_assignments a ON a.workspace_id=f.workspace_id AND a.task_id=f.task_id
              WHERE f.workspace_id=? AND f.brief_id=? ORDER BY f.created_at,f.id LIMIT 150''',(wid,bid))]
        reviews=[dict(x) for x in db.execute('''SELECT id,reviewer_id,decision,rationale,snapshot_fingerprint,created_at
              FROM team_brief_reviews WHERE workspace_id=? AND brief_id=? ORDER BY created_at,id LIMIT 100''',(wid,bid))]
        current=compute_brief(db,wid,row['investigation_id'],storage)
        fresh=current['fingerprint']==row['fingerprint']
        rejected=any(r['decision']=='changes_requested' for r in reviews)
        approved=any(r['decision']=='accept_for_demo' for r in reviews)
        outstanding=any(t['status'] not in ('done','cancelled') for t in followups)
        # Human acceptance is not scientific, model, or runtime certification.
        review_state=('source_changed' if not fresh else 'changes_requested' if rejected
                      else 'open_followups' if outstanding else 'human_accepted' if approved else 'awaiting_human_review')
        return {'brief_id':bid,'investigation_id':row['investigation_id'],'title':row['title'],
          'snapshot_fingerprint':row['fingerprint'],'saved_snapshot_intact':True,'matches_current_evidence':fresh,
          'review_state':review_state,'comments':comments,'followups':followups,'reviews':reviews,
          'model_invoked':False,'tests_executed':False,'human_acceptance_is_not_independent_verification':True}

    @router.get('/workspaces/{wid}/brief-collaboration/{bid}')
    def get(wid:str,bid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            row,snap=brief(db,wid,bid)
            return aggregate(db,wid,bid,row,snap)

    @router.post('/workspaces/{wid}/brief-collaboration/{bid}/comments',status_code=201)
    def comment(wid:str,bid:str,body:BriefComment,request:Request):
        who=actor(request)
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            row,snap=brief(db,wid,bid)
            sourcehash=None
            if body.source_file_id:
                found=next((s for s in snap['sources'] if s['id']==body.source_file_id),None)
                if not found:raise HTTPException(422,'Source is not part of the saved brief')
                sourcehash=found['pinned_sha256']
            cid=uuid.uuid4().hex
            db.execute('INSERT INTO team_brief_comments VALUES(?,?,?,?,?,?,?,?,?)',
                (cid,wid,bid,row['investigation_id'],who['id'],body.body.strip(),body.source_file_id,sourcehash,now()))
            event(db,wid,who,'brief_comment',cid,{'brief_id':bid,'source_file_id':body.source_file_id})
        return {'id':cid,'source_sha256':sourcehash,'saved':True}

    @router.post('/workspaces/{wid}/brief-collaboration/{bid}/followups',status_code=201)
    def followup(wid:str,bid:str,body:BriefFollowup,request:Request):
        who=actor(request)
        if body.priority not in ('low','normal','high','urgent'):raise HTTPException(422,'Invalid priority')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'editor')
            row,snap=brief(db,wid,bid)
            if body.assignee_id and not db.execute('SELECT 1 FROM collab_memberships WHERE workspace_id=? AND user_id=?',(wid,body.assignee_id)).fetchone():
                raise HTTPException(422,'Assignee is not in this workspace')
            tid=uuid.uuid4().hex; fid=uuid.uuid4().hex;stamp=now()
            db.execute('INSERT INTO collab_tasks VALUES(?,?,?,?,?,?,?,?,?,?)',
                (tid,wid,row['project_id'],body.title.strip(),body.description.strip(),body.priority,'open',who['id'],stamp,stamp))
            db.execute('INSERT INTO team_brief_followups VALUES(?,?,?,?,?,?)',(fid,wid,bid,tid,who['id'],stamp))
            if body.assignee_id:
                db.execute('INSERT INTO team_task_assignments VALUES(?,?,?,?,?,?)',
                    (wid,tid,body.assignee_id,who['id'],'Follow-up from saved investigation brief',stamp))
            event(db,wid,who,'brief_followup_created',fid,{'brief_id':bid,'task_id':tid})
        return {'id':fid,'task_id':tid,'task_status':'open','created':True}

    @router.post('/workspaces/{wid}/brief-collaboration/{bid}/reviews',status_code=201)
    def review(wid:str,bid:str,body:ReviewDecision,request:Request):
        who=actor(request)
        if body.decision not in ('accept_for_demo','changes_requested'):
            raise HTTPException(422,'Invalid review decision')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');member(db,wid,who,'admin')
            row,snap=brief(db,wid,bid)
            if row['created_by']==who['id']:raise HTTPException(403,'Author cannot independently review own brief')
            current=compute_brief(db,wid,row['investigation_id'],storage)
            if current['fingerprint']!=row['fingerprint']:
                raise HTTPException(409,'Brief is stale; save an updated brief before review')
            if db.execute('SELECT 1 FROM team_brief_reviews WHERE workspace_id=? AND brief_id=? AND reviewer_id=?',(wid,bid,who['id'])).fetchone():
                raise HTTPException(409,'Reviewer decision is already recorded')
            if body.decision=='accept_for_demo':
                pending=db.execute('''SELECT COUNT(*) AS n FROM team_brief_followups f JOIN collab_tasks t ON t.id=f.task_id
                    WHERE f.workspace_id=? AND f.brief_id=? AND t.status NOT IN ('done','cancelled')''',(wid,bid)).fetchone()['n']
                if pending:raise HTTPException(409,'Open follow-ups prevent demo acceptance')
            rid=uuid.uuid4().hex
            db.execute('INSERT INTO team_brief_reviews VALUES(?,?,?,?,?,?,?,?)',
                (rid,wid,bid,who['id'],body.decision,body.rationale.strip(),row['fingerprint'],now()))
            event(db,wid,who,'brief_human_review',rid,{'brief_id':bid,'decision':body.decision})
        return {'id':rid,'decision':body.decision,'human_only':True,'independent_model_verification':False}
