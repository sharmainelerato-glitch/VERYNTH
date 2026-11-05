"""NESSON collaboration foundation: owner-scoped workspaces and persistent tasks.

The existing single-owner access gate protects this router. This module does NOT
claim multiuser authentication, invitations, or cross-user sharing are available.
"""
import hashlib
import json
import sqlite3
import uuid
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

OWNER_ID='legacy-owner'
PERSONAL_ID='personal-owner-workspace'

class NewWorkspace(BaseModel):
    name: str = Field(min_length=1,max_length=120)

class NewTask(BaseModel):
    title: str = Field(min_length=1,max_length=160)
    description: str = Field(default='',max_length=6000)
    priority: str = 'normal'
    project_id: str | None = None

class UpdateTask(BaseModel):
    status: str
    note: str = Field(min_length=3,max_length=2000)

class LinkProject(BaseModel):
    project_id: str

def register_collaboration(app, connection, now):
    router=APIRouter(prefix='/api/collaboration',tags=['collaboration-foundation'])

    def initialize():
        with connection() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS collab_workspaces(
                id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('personal','team')),
                owner_user_id TEXT NOT NULL,created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS collab_memberships(
                workspace_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,
                created_at TEXT NOT NULL,PRIMARY KEY(workspace_id,user_id),
                FOREIGN KEY(workspace_id) REFERENCES collab_workspaces(id));
            CREATE TABLE IF NOT EXISTS collab_project_links(
                project_id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,linked_at TEXT NOT NULL,
                FOREIGN KEY(workspace_id) REFERENCES collab_workspaces(id));
            CREATE TABLE IF NOT EXISTS collab_tasks(
                id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,project_id TEXT,title TEXT NOT NULL,
                description TEXT NOT NULL,priority TEXT NOT NULL,status TEXT NOT NULL,
                requested_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS collab_events(
                id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,actor TEXT NOT NULL,
                event_type TEXT NOT NULL,object_id TEXT NOT NULL,details_json TEXT NOT NULL,created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ix_collab_tasks_workspace ON collab_tasks(workspace_id,created_at);
            CREATE INDEX IF NOT EXISTS ix_collab_events_workspace ON collab_events(workspace_id,created_at);
            ''')
            timestamp=now()
            db.execute('INSERT OR IGNORE INTO collab_workspaces VALUES(?,?,?,?,?)',
                       (PERSONAL_ID,'My workspace','personal',OWNER_ID,timestamp))
            db.execute('INSERT OR IGNORE INTO collab_memberships VALUES(?,?,?,?)',
                       (PERSONAL_ID,OWNER_ID,'owner',timestamp))
            # Idempotent migration: never rewrite an existing project-workspace mapping.
            db.execute('''INSERT OR IGNORE INTO collab_project_links(project_id,workspace_id,linked_at)
                          SELECT id,?,? FROM projects''',(PERSONAL_ID,timestamp))

    initialize()

    def workspace(db,wid):
        row=db.execute('''SELECT w.* FROM collab_workspaces w
          JOIN collab_memberships m ON m.workspace_id=w.id
          WHERE w.id=? AND m.user_id=?''',(wid,OWNER_ID)).fetchone()
        if row is None:raise HTTPException(404,'Workspace not found')
        return dict(row)

    def event(db,wid,kind,object_id,details):
        db.execute('INSERT INTO collab_events VALUES(?,?,?,?,?,?,?)',
                   (uuid.uuid4().hex,wid,OWNER_ID,kind,object_id,json.dumps(details,sort_keys=True),now()))

    @router.get('/status')
    def status():
        return {'authentication_mode':'single_owner','multiuser_enabled':False,
                'invitations_enabled':False,'isolated_execution_enabled':False,
                'message':'Workspace records and owner tasks are functional. Multiuser access and invitations are not yet enabled.'}

    @router.get('/workspaces')
    def list_workspaces():
        with connection() as db:
            return [dict(r) for r in db.execute('''SELECT w.*,m.role FROM collab_workspaces w
              JOIN collab_memberships m ON w.id=m.workspace_id WHERE m.user_id=? ORDER BY w.created_at''',(OWNER_ID,))]

    @router.post('/workspaces',status_code=201)
    def create_workspace(body:NewWorkspace):
        name=body.name.strip()
        if not name:raise HTTPException(422,'Workspace name must not be blank')
        wid=uuid.uuid4().hex
        with connection() as db:
            db.execute('INSERT INTO collab_workspaces VALUES(?,?,?,?,?)',(wid,name,'team',OWNER_ID,now()))
            db.execute('INSERT INTO collab_memberships VALUES(?,?,?,?)',(wid,OWNER_ID,'owner',now()))
            event(db,wid,'workspace_created',wid,{'name':name})
        return {'id':wid,'name':name,'kind':'team','role':'owner','sharing_enabled':False}

    @router.get('/workspaces/{wid}')
    def get_workspace(wid:str):
        with connection() as db:
            result=workspace(db,wid)
            result['role']='owner'
            result['sharing_enabled']=False
            result['projects']=[dict(r) for r in db.execute('''SELECT p.id,p.name,p.created_at FROM projects p
               JOIN collab_project_links c ON c.project_id=p.id WHERE c.workspace_id=? ORDER BY p.created_at DESC''',(wid,))]
            return result

    @router.post('/workspaces/{wid}/projects/create',status_code=201)
    def create_workspace_project(wid:str,body:NewWorkspace):
        name=body.name.strip()
        if not name:raise HTTPException(422,'Project name must not be blank')
        pid=uuid.uuid4().hex
        with connection() as db:
            workspace(db,wid)
            created=now()
            db.execute('INSERT INTO projects VALUES(?,?,?)',(pid,name,created))
            db.execute('INSERT INTO collab_project_links VALUES(?,?,?)',(pid,wid,created))
            event(db,wid,'project_created',pid,{'name':name})
        return {'id':pid,'name':name,'workspace_id':wid,'created_at':created}

    @router.post('/workspaces/{wid}/projects',status_code=201)
    def link_project(wid:str,body:LinkProject):
        with connection() as db:
            workspace(db,wid)
            project=db.execute('SELECT id FROM projects WHERE id=?',(body.project_id,)).fetchone()
            if not project:raise HTTPException(404,'Project not found')
            linked=db.execute('SELECT workspace_id FROM collab_project_links WHERE project_id=?',(body.project_id,)).fetchone()
            if linked:
                if linked['workspace_id']==wid:raise HTTPException(409,'Project already linked')
                raise HTTPException(409,'Project already belongs to a workspace; transfer requires a separate approved workflow')
            db.execute('INSERT INTO collab_project_links VALUES(?,?,?)',(body.project_id,wid,now()))
            event(db,wid,'project_linked',body.project_id,{})
        return {'linked':True,'project_id':body.project_id,'workspace_id':wid}

    @router.post('/workspaces/{wid}/tasks',status_code=201)
    def create_task(wid:str,body:NewTask):
        title=body.title.strip()
        if not title:raise HTTPException(422,'Task title must not be blank')
        if body.priority not in ('low','normal','high','urgent'):raise HTTPException(422,'Invalid priority')
        tid=uuid.uuid4().hex
        with connection() as db:
            workspace(db,wid)
            if body.project_id:
                linked=db.execute('SELECT 1 FROM collab_project_links WHERE project_id=? AND workspace_id=?',(body.project_id,wid)).fetchone()
                if not linked:raise HTTPException(403,'Project does not belong to this workspace')
            stamp=now()
            db.execute('INSERT INTO collab_tasks VALUES(?,?,?,?,?,?,?,?,?,?)',
              (tid,wid,body.project_id,title,body.description,body.priority,'open',OWNER_ID,stamp,stamp))
            event(db,wid,'task_created',tid,{'priority':body.priority,'project_id':body.project_id})
        return {'id':tid,'workspace_id':wid,'title':title,'status':'open','priority':body.priority}

    @router.get('/workspaces/{wid}/tasks')
    def list_tasks(wid:str):
        with connection() as db:
            workspace(db,wid)
            return [dict(r) for r in db.execute('SELECT * FROM collab_tasks WHERE workspace_id=? ORDER BY created_at DESC',(wid,))]

    @router.post('/workspaces/{wid}/tasks/{tid}/status')
    def set_task_status(wid:str,tid:str,body:UpdateTask):
        if body.status not in ('open','in_progress','blocked','done','cancelled'):
            raise HTTPException(422,'Invalid status')
        with connection() as db:
            workspace(db,wid)
            row=db.execute('SELECT status FROM collab_tasks WHERE workspace_id=? AND id=?',(wid,tid)).fetchone()
            if not row:raise HTTPException(404,'Task not found')
            if row['status'] in ('done','cancelled'):
                raise HTTPException(409,'Completed or cancelled tasks cannot change status')
            allowed={'open':{'in_progress','blocked','cancelled'},
                     'in_progress':{'blocked','done','cancelled'},
                     'blocked':{'in_progress','cancelled'}}
            if body.status not in allowed[row['status']]:raise HTTPException(409,'Invalid task transition')
            db.execute('UPDATE collab_tasks SET status=?,updated_at=? WHERE id=? AND workspace_id=?',
                       (body.status,now(),tid,wid))
            event(db,wid,'task_status_changed',tid,{'from':row['status'],'to':body.status,'note':body.note})
        return {'id':tid,'status':body.status}

    @router.get('/workspaces/{wid}/activity')
    def activity(wid:str):
        with connection() as db:
            workspace(db,wid)
            return [dict(r) for r in db.execute('SELECT * FROM collab_events WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100',(wid,))]

    app.include_router(router)
