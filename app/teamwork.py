"""NESSON collaboration security boundary.

Owner keeps existing legacy APIs. Invited users access ONLY /api/team routes;
all object reads/writes enforce workspace membership and role. No code execution.
"""
import os
import smtplib
import ssl
from email.message import EmailMessage
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request, File, UploadFile
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from pydantic import BaseModel, Field

TEAM_COOKIE='nesson_team_session'
OWNER='legacy-owner'
ROLES={'owner':4,'admin':3,'editor':2,'viewer':1}
TOKEN_LIFETIME=12*3600
INVITE_LIFETIME=7*86400
LOGIN_FAILURES={}  # Local-only throttle; distributed deployments require shared rate limits.

def _hash_token(value):return hashlib.sha256(value.encode('utf-8')).hexdigest()

def _password_hash(password):
    salt=secrets.token_bytes(16)
    return f'{salt.hex()}${hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000).hex()}'

def _password_ok(password, stored):
    try:
        salt,digest=stored.split('$')
        candidate=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),310000).hex()
        return hmac.compare_digest(candidate,digest)
    except (ValueError,TypeError):return False

def _email(value):
    email=value.strip().lower()
    if len(email)>254 or not re.fullmatch(r'[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}',email):
        raise HTTPException(422,'Valid email required')
    return email

def _new_id():return uuid.uuid4().hex

def get_team_actor(request, connection, secret):
    token=request.cookies.get(TEAM_COOKIE,'')
    if len(token)<30 or len(token)>256:return None
    # Opaque random tokens: DB contains only the hash, never the bearer secret.
    with connection() as db:
        row=db.execute('''SELECT u.id,u.email,u.display_name FROM team_sessions s
             JOIN team_users u ON u.id=s.user_id
             WHERE s.token_hash=? AND s.expires_at>? AND u.disabled=0''',
             (_hash_token(token),int(time.time()))).fetchone()
        return dict(row) if row else None

class Invitation(BaseModel):
    email:str
    role:str='editor'
class InvitationAccept(BaseModel):
    token:str=Field(min_length=40,max_length=256)
    display_name:str=Field(min_length=1,max_length=80)
    password:str=Field(min_length=12,max_length=200)
class ProfileUpdate(BaseModel):
    display_name:str=Field(min_length=1,max_length=80)

class PasswordChange(BaseModel):
    current_password:str
    new_password:str=Field(min_length=12,max_length=200)

class MemberLogin(BaseModel):
    email:str
    password:str
class NewTask(BaseModel):
    title:str=Field(min_length=1,max_length=160)
    description:str=Field(default='',max_length=6000)
    priority:str='normal'
    project_id:str|None=None
class TaskStatus(BaseModel):
    status:str
    note:str=Field(min_length=3,max_length=2000)
class ChangeRole(BaseModel):
    role:str

class Note(BaseModel):
    body:str=Field(min_length=1,max_length=4000)


def register_teamwork(app, connection, now, owner_auth, secret, storage, read_tool=None):
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS team_users(
          id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,display_name TEXT NOT NULL,
          password_hash TEXT NOT NULL,disabled INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS team_sessions(
          token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires_at INTEGER NOT NULL,
          created_at TEXT NOT NULL,FOREIGN KEY(user_id) REFERENCES team_users(id));
        CREATE TABLE IF NOT EXISTS team_invitations(
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,email TEXT NOT NULL,
          role TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,
          created_by TEXT NOT NULL,expires_at INTEGER NOT NULL,
          accepted_by TEXT,accepted_at TEXT,revoked_at TEXT,created_at TEXT NOT NULL,
          FOREIGN KEY(workspace_id) REFERENCES collab_workspaces(id));
        CREATE TABLE IF NOT EXISTS team_discussions(
          id TEXT PRIMARY KEY,workspace_id TEXT NOT NULL,actor_id TEXT NOT NULL,
          body TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS ix_team_discussions_workspace ON team_discussions(workspace_id,created_at);
        CREATE INDEX IF NOT EXISTS ix_team_invites_workspace ON team_invitations(workspace_id,created_at);
        ''')
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS team_message_attachments(
          message_id TEXT NOT NULL, workspace_id TEXT NOT NULL,
          project_id TEXT NOT NULL, file_id TEXT NOT NULL,
          PRIMARY KEY(message_id,file_id));
        CREATE INDEX IF NOT EXISTS ix_team_message_att_workspace ON team_message_attachments(workspace_id);
        """)
    with connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS team_notifications(
          id TEXT PRIMARY KEY, recipient_id TEXT NOT NULL, workspace_id TEXT,
          kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL,
          created_at TEXT NOT NULL, read_at TEXT);
        CREATE INDEX IF NOT EXISTS ix_team_notifications_recipient
          ON team_notifications(recipient_id,created_at);
        """)
    router=APIRouter(prefix='/api/team',tags=['team-workspaces'])

    def actor(request):
        if owner_auth(request):return {'id':OWNER,'display_name':'Workspace owner','email':None,'owner':True}
        user=get_team_actor(request,connection,secret)
        if user:return {**user,'owner':False}
        raise HTTPException(401,'Sign in required')

    def member(db,wid,who,level='viewer'):
        role=db.execute('''SELECT m.role FROM collab_memberships m
            JOIN collab_workspaces w ON w.id=m.workspace_id
            WHERE m.workspace_id=? AND m.user_id=?''',(wid,who['id'])).fetchone()
        if not role:raise HTTPException(404,'Workspace not found')
        if ROLES.get(role['role'],0)<ROLES[level]:raise HTTPException(403,'Insufficient workspace permissions')
        return role['role']

    def event(db,wid,who,etype,oid,details):
        db.execute('INSERT INTO collab_events VALUES(?,?,?,?,?,?,?)',
                   (_new_id(),wid,who['id'],etype,oid,json.dumps(details,sort_keys=True),now()))

    def add_notification(db,recipient_id,wid,kind,title,body):
        db.execute('INSERT INTO team_notifications VALUES(?,?,?,?,?,?,?,NULL)',
                   (_new_id(),recipient_id,wid,kind,title,body,now()))

    @router.get('/notifications')
    def notifications(request:Request):
        who=actor(request)
        with connection() as db:
            rows=db.execute('''SELECT id,workspace_id,kind,title,body,created_at,read_at
               FROM team_notifications WHERE recipient_id=? ORDER BY created_at DESC LIMIT 100''',(who['id'],)).fetchall()
            unread=db.execute('SELECT count(*) FROM team_notifications WHERE recipient_id=? AND read_at IS NULL',(who['id'],)).fetchone()[0]
            return {'items':[dict(row) for row in rows],'unread':unread}

    @router.post('/notifications/{nid}/read')
    def read_notification(nid:str,request:Request):
        who=actor(request)
        with connection() as db:
            result=db.execute('UPDATE team_notifications SET read_at=COALESCE(read_at,?) WHERE id=? AND recipient_id=?',(now(),nid,who['id']))
            if result.rowcount==0:raise HTTPException(404,'Notification not found')
        return {'read':True}

    def send_invitation_email(address,workspace_name,role,token):
        host=os.getenv('VERYNTH_SMTP_HOST','').strip()
        sender=os.getenv('VERYNTH_EMAIL_FROM','').strip()
        if not host or not sender:return False,'not_configured'
        base=os.getenv('VERYNTH_PUBLIC_URL','').strip().rstrip('/')
        if not base.startswith('https://'):
            return False,'public_https_url_required'
        msg=EmailMessage()
        msg['Subject']='Your VERYNTH workspace invitation'
        msg['From']=sender
        msg['To']=address
        msg.set_content(f'You have been invited to {workspace_name} as {role}.\n\nOpen {base}/team/login and choose Accept a workspace invitation.\n\nYour one-time invitation code is: {token}\n\nExpires in 7 days. If you did not expect this invitation, ignore this email.')
        port=int(os.getenv('VERYNTH_SMTP_PORT','465'))
        username=os.getenv('VERYNTH_SMTP_USERNAME','')
        password=os.getenv('VERYNTH_SMTP_PASSWORD','')
        try:
            if port==465:
                with smtplib.SMTP_SSL(host,port,timeout=12,context=ssl.create_default_context()) as smtp:
                    if username:smtp.login(username,password)
                    smtp.send_message(msg)
            else:
                with smtplib.SMTP(host,port,timeout=12) as smtp:
                    smtp.starttls(context=ssl.create_default_context())
                    if username:smtp.login(username,password)
                    smtp.send_message(msg)
            return True,'smtp_accepted'
        except (OSError,smtplib.SMTPException,ValueError):
            return False,'delivery_failed'

    def workspace_info(db,wid,who):
        role=member(db,wid,who)
        row=db.execute('SELECT id,name,kind,created_at FROM collab_workspaces WHERE id=?',(wid,)).fetchone()
        return {**dict(row),'role':role}

    @router.post('/auth/login')
    def login(body:MemberLogin,request:Request):
        email=_email(body.email)
        key=(request.client.host if request.client else 'unknown',email)
        recent=[t for t in LOGIN_FAILURES.get(key,[]) if time.time()-t<900]
        if len(recent)>=8:raise HTTPException(429,'Too many attempts')
        with connection() as db:
            u=db.execute('SELECT * FROM team_users WHERE email=? AND disabled=0',(email,)).fetchone()
            if not u or not _password_ok(body.password,u['password_hash']):
                recent.append(time.time());LOGIN_FAILURES[key]=recent
                raise HTTPException(401,'Invalid credentials')
            LOGIN_FAILURES.pop(key,None)
            token=secrets.token_urlsafe(48)
            db.execute('INSERT INTO team_sessions VALUES(?,?,?,?)',
                       (_hash_token(token),u['id'],int(time.time())+TOKEN_LIFETIME,now()))
        reply=JSONResponse({'authenticated':True,'user':{'id':u['id'],'display_name':u['display_name']}})
        reply.set_cookie(TEAM_COOKIE,token,max_age=TOKEN_LIFETIME,httponly=True,
                         secure=request.url.scheme=='https',samesite='strict',path='/')
        return reply

    @router.post('/auth/invitations/accept',status_code=201)
    def accept(body:InvitationAccept,request:Request):
        display=body.display_name.strip()
        if not display:raise HTTPException(422,'Display name required')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            invitation=db.execute('''SELECT * FROM team_invitations WHERE token_hash=?''',(_hash_token(body.token),)).fetchone()
            if not invitation or invitation['accepted_at'] or invitation['revoked_at'] or invitation['expires_at']<=time.time():
                raise HTTPException(400,'Invitation invalid or expired')
            u=db.execute('SELECT * FROM team_users WHERE email=?',(invitation['email'],)).fetchone()
            if u:
                if u['disabled'] or not _password_ok(body.password,u['password_hash']):
                    raise HTTPException(401,'Invalid credentials')
                user_id=u['id']
            else:
                user_id=_new_id()
                db.execute('INSERT INTO team_users VALUES(?,?,?,?,?,?)',
                           (user_id,invitation['email'],display,_password_hash(body.password),0,now()))
            existing=db.execute('SELECT 1 FROM collab_memberships WHERE workspace_id=? AND user_id=?',
                                 (invitation['workspace_id'],user_id)).fetchone()
            if existing:raise HTTPException(409,'Already a member')
            db.execute('INSERT INTO collab_memberships VALUES(?,?,?,?)',
                       (invitation['workspace_id'],user_id,invitation['role'],now()))
            db.execute('UPDATE team_invitations SET accepted_by=?,accepted_at=? WHERE id=?',
                       (user_id,now(),invitation['id']))
            event(db,invitation['workspace_id'],{'id':user_id},'invitation_accepted',invitation['id'],{'role':invitation['role']})
            add_notification(db,user_id,invitation['workspace_id'],'invitation_accepted','Workspace joined','Your invitation was accepted. You can now collaborate.')
            if invitation['created_by'] != user_id:
                add_notification(db,invitation['created_by'],invitation['workspace_id'],'invitation_accepted','Invitation accepted','A teammate accepted your workspace invitation.')
        return {'accepted':True,'workspace_id':invitation['workspace_id'],'next':'Sign in via /team/login'}

    @router.post('/auth/logout')
    def logout(request:Request):
        # Does not log owner out of the main NESSON app.
        token=request.cookies.get(TEAM_COOKIE,'')
        with connection() as db:
            db.execute('DELETE FROM team_sessions WHERE token_hash=?',(_hash_token(token),))
        reply=JSONResponse({'signed_out':True})
        reply.delete_cookie(TEAM_COOKIE,path='/')
        return reply

    @router.patch('/profile')
    def update_profile(body:ProfileUpdate,request:Request):
        who=actor(request)
        if who['id']==OWNER:raise HTTPException(403,'Owner profile is managed by the personal account')
        display=body.display_name.strip()
        if not display:raise HTTPException(422,'Display name required')
        with connection() as db:
            db.execute('UPDATE team_users SET display_name=? WHERE id=? AND disabled=0',(display,who['id']))
            add_notification(db,who['id'],None,'profile_updated','Profile updated','Your VERYNTH display name was changed.')
        return {'display_name':display,'saved':True}

    @router.post('/auth/change-password')
    def change_password(body:PasswordChange,request:Request):
        who=actor(request)
        if who['id']==OWNER:raise HTTPException(403,'Use personal account security settings')
        if body.current_password==body.new_password:raise HTTPException(422,'Choose a different password')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            u=db.execute('SELECT password_hash FROM team_users WHERE id=? AND disabled=0',(who['id'],)).fetchone()
            if not u or not _password_ok(body.current_password,u['password_hash']):
                raise HTTPException(401,'Current password is incorrect')
            db.execute('UPDATE team_users SET password_hash=? WHERE id=?',(_password_hash(body.new_password),who['id']))
            token=request.cookies.get(TEAM_COOKIE,'')
            db.execute('DELETE FROM team_sessions WHERE user_id=? AND token_hash<>?',(who['id'],_hash_token(token)))
            add_notification(db,who['id'],None,'security','Password changed','Your password was changed. Other team sessions were signed out.')
        return {'changed':True,'other_sessions_revoked':True}

    @router.post('/notifications/read-all')
    def read_all_notifications(request:Request):
        who=actor(request)
        with connection() as db:
            result=db.execute('UPDATE team_notifications SET read_at=? WHERE recipient_id=? AND read_at IS NULL',(now(),who['id']))
        return {'marked_read':result.rowcount}

    @router.get('/me')
    def me(request:Request):
        who=actor(request)
        return {'id':who['id'],'display_name':who['display_name'],'owner':who['owner']}

    @router.get('/workspaces')
    def list_workspaces(request:Request):
        who=actor(request)
        with connection() as db:
            return [dict(r) for r in db.execute('''SELECT w.id,w.name,w.kind,m.role
                FROM collab_workspaces w JOIN collab_memberships m ON w.id=m.workspace_id
                WHERE m.user_id=? ORDER BY w.created_at DESC''',(who['id'],))]

    @router.get('/workspaces/{wid}')
    def workspace(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            return workspace_info(db,wid,who)

    @router.get('/workspaces/{wid}/members')
    def members(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT m.user_id,m.role,
                  CASE WHEN m.user_id=? THEN 'Workspace owner' ELSE u.display_name END display_name
                  FROM collab_memberships m LEFT JOIN team_users u ON u.id=m.user_id
                  WHERE m.workspace_id=? ORDER BY m.created_at''',(OWNER,wid))]

    @router.post('/workspaces/{wid}/invitations',status_code=201)
    def invite(wid:str,body:Invitation,request:Request):
        who=actor(request)
        email=_email(body.email)
        if body.role not in ('admin','editor','viewer'):raise HTTPException(422,'Invalid role')
        token=secrets.token_urlsafe(48)
        iid=_new_id()
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            member(db,wid,who,'admin')
            w=db.execute('SELECT kind,name FROM collab_workspaces WHERE id=?',(wid,)).fetchone()
            if w['kind']!='team':raise HTTPException(403,'Personal workspaces cannot invite teammates')
            prior=db.execute('''SELECT id FROM team_invitations
                   WHERE workspace_id=? AND email=? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at>?''',
                   (wid,email,int(time.time()))).fetchone()
            if prior:raise HTTPException(409,'Pending invitation already exists for this address')
            user=db.execute('SELECT id FROM team_users WHERE email=?',(email,)).fetchone()
            if user and db.execute('SELECT 1 FROM collab_memberships WHERE user_id=? AND workspace_id=?',
                                   (user['id'],wid)).fetchone():raise HTTPException(409,'Already a member')
            db.execute('INSERT INTO team_invitations VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (iid,wid,email,body.role,_hash_token(token),who['id'],int(time.time())+INVITE_LIFETIME,None,None,None,now()))
            event(db,wid,who,'invitation_created',iid,{'role':body.role})
        delivered,delivery=send_invitation_email(email,w['name'],body.role,token)
        with connection() as db:
            add_notification(db,who['id'],wid,'invitation_created','Invitation created',
                             'Email invitation accepted by SMTP server.' if delivered else 'Invitation saved; email was not sent ('+delivery+').')
            if user:
                add_notification(db,user['id'],wid,'invitation_received','Workspace invitation',
                                 'You have been invited to join '+w['name']+'. Check your email or contact the inviter.')
        # SMTP acceptance is not proof of inbox delivery.
        return {'id':iid,'invitation_code':token,'expires_in_days':7,
                'delivery':delivery,'email_sent':delivered,
                'warning':None if delivered else 'Email not sent. Share the one-time code securely.'}

    @router.get('/workspaces/{wid}/invitations')
    def invitations(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who,'admin')
            return [dict(r) for r in db.execute('''SELECT id,email,role,created_at,expires_at,accepted_at,revoked_at
                FROM team_invitations WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100''',(wid,))]

    @router.post('/workspaces/{wid}/invitations/{iid}/revoke')
    def revoke(wid:str,iid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who,'admin')
            result=db.execute('''UPDATE team_invitations SET revoked_at=? WHERE id=? AND workspace_id=?
                    AND accepted_at IS NULL AND revoked_at IS NULL''',(now(),iid,wid))
            if result.rowcount!=1:raise HTTPException(404,'Pending invitation not found')
            event(db,wid,who,'invitation_revoked',iid,{})
        return {'revoked':True}

    @router.post('/workspaces/{wid}/members/{user_id}/role')
    def change_role(wid:str,user_id:str,body:ChangeRole,request:Request):
        who=actor(request)
        if body.role not in ('admin','editor','viewer'):raise HTTPException(422,'Invalid role')
        if user_id==OWNER:raise HTTPException(403,'Cannot modify workspace owner')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            member(db,wid,who,'owner')
            result=db.execute('UPDATE collab_memberships SET role=? WHERE workspace_id=? AND user_id=?',
                              (body.role,wid,user_id))
            if result.rowcount!=1:raise HTTPException(404,'Member not found')
            event(db,wid,who,'member_role_changed',user_id,{'role':body.role})
        return {'user_id':user_id,'role':body.role}

    @router.post('/workspaces/{wid}/members/{user_id}/remove')
    def remove_member(wid:str,user_id:str,request:Request):
        who=actor(request)
        if user_id==OWNER:raise HTTPException(403,'Cannot remove workspace owner')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            member(db,wid,who,'owner')
            removed=db.execute('DELETE FROM collab_memberships WHERE workspace_id=? AND user_id=?',
                               (wid,user_id))
            if removed.rowcount!=1:raise HTTPException(404,'Member not found')
            event(db,wid,who,'member_removed',user_id,{})
        return {'removed':True}

    # Team-scoped specialist reads: membership and project link are checked on EVERY call.
    # Do not route through the legacy owner API or expose arbitrary tool names.
    @router.get('/workspaces/{wid}/projects/{pid}/specialists/{specialist}')
    def team_specialist(wid:str,pid:str,specialist:str,request:Request):
        who=actor(request)
        allow={'investigation':'list_intelligence_cases',
               'reliability':'get_reliability_overview',
               'reality-twin':'list_reality_twins',
               'engineering':'get_engineering_verification_plan',
               'ai-council':'list_ai_council_reports',
               'files':'list_project_files'}
        if specialist not in allow:raise HTTPException(404,'Specialist unavailable')
        with connection() as db:
            member(db,wid,who,'viewer')
            linked=db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,pid)).fetchone()
            if not linked:raise HTTPException(404,'Project not found in workspace')
        if read_tool is None:raise HTTPException(503,'Specialist adapter not configured')
        result=read_tool(pid,allow[specialist],{})
        return {'project_id':pid,'specialist':specialist,'data':result,
                'new_analysis_performed':False,'scope':'workspace-linked project'}

    @router.get('/workspaces/{wid}/projects')
    def projects(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT p.id,p.name,p.created_at
                FROM projects p JOIN collab_project_links l ON l.project_id=p.id
                WHERE l.workspace_id=? ORDER BY p.created_at DESC''',(wid,))]

    @router.post('/workspaces/{wid}/projects/{pid}/files',status_code=201)
    async def upload_shared_file(wid:str,pid:str,request:Request,file:UploadFile=File(...)):
        who=actor(request)
        with connection() as db:
            member(db,wid,who,'editor')
            if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',
                              (wid,pid)).fetchone():raise HTTPException(404,'Project not found')
        name=Path(file.filename or '').name.strip()
        if not name or len(name)>180:raise HTTPException(422,'Invalid filename')
        fid=_new_id()
        destination=Path(storage)/fid
        digest=hashlib.sha256();total=0
        try:
            with destination.open('xb') as out:
                while True:
                    chunk=await file.read(1024*1024)
                    if not chunk:break
                    total+=len(chunk)
                    if total>15*1024*1024:raise HTTPException(413,'Team file exceeds 15 MB limit')
                    digest.update(chunk);out.write(chunk)
            with connection() as db:
                db.execute('BEGIN IMMEDIATE')
                member(db,wid,who,'editor')
                if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',
                                  (wid,pid)).fetchone():raise HTTPException(404,'Project not found')
                db.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (fid,pid,name,file.content_type or 'application/octet-stream',total,digest.hexdigest(),
                            str(destination.resolve()),'', 'stored_not_processed',now()))
                event(db,wid,who,'file_uploaded',fid,{'project_id':pid,'filename':name,'bytes':total})
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        finally:
            await file.close()
        return {'id':fid,'filename':name,'bytes':total,'sha256':digest.hexdigest(),
                'processing':'not_processed','meaning':'Shared file stored only; no AI analysis was run'}

    @router.get('/workspaces/{wid}/projects/{pid}/files')
    def files(wid:str,pid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            if not db.execute('SELECT 1 FROM collab_project_links WHERE project_id=? AND workspace_id=?',(pid,wid)).fetchone():
                raise HTTPException(404,'Project not found')
            return [dict(r) for r in db.execute('''SELECT id,filename,mime,size,sha256,created_at FROM files
                WHERE project_id=? ORDER BY created_at DESC LIMIT 200''',(pid,))]

    @router.get('/workspaces/{wid}/projects/{pid}/files/{fid}/download')
    def download(wid:str,pid:str,fid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            linked=db.execute('SELECT 1 FROM collab_project_links WHERE project_id=? AND workspace_id=?',(pid,wid)).fetchone()
            if not linked:raise HTTPException(404,'Project not found')
            f=db.execute('SELECT * FROM files WHERE id=? AND project_id=?',(fid,pid)).fetchone()
        if not f:raise HTTPException(404,'File not found')
        # Existing file-storage convention: stored evidence has UUID ID filenames.
        actual=Path(f['storage_path']).resolve()
        root=Path(storage).resolve()
        if actual.parent!=root or actual.name!=fid:raise HTTPException(409,'Unsafe stored file path')
        if not actual.is_file():raise HTTPException(404,'File missing')
        digest=hashlib.sha256()
        with actual.open('rb') as content:
            for chunk in iter(lambda:content.read(1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=f['sha256']:
            raise HTTPException(409,'File integrity failed')
        return FileResponse(actual,filename=f['filename'],media_type='application/octet-stream')

    @router.get('/workspaces/{wid}/tasks')
    def tasks(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT t.*,COALESCE(u.display_name,'Workspace owner') as requested_by_name
                FROM collab_tasks t LEFT JOIN team_users u ON u.id=t.requested_by
                WHERE t.workspace_id=? ORDER BY t.created_at DESC LIMIT 200''',(wid,))]

    @router.post('/workspaces/{wid}/tasks',status_code=201)
    def new_task(wid:str,body:NewTask,request:Request):
        who=actor(request)
        if not body.title.strip():raise HTTPException(422,'Title required')
        if body.priority not in ('low','normal','high','urgent'):raise HTTPException(422,'Invalid priority')
        with connection() as db:
            member(db,wid,who,'editor')
            if body.project_id and not db.execute('SELECT 1 FROM collab_project_links WHERE project_id=? AND workspace_id=?',
                          (body.project_id,wid)).fetchone():raise HTTPException(403,'Project is outside workspace')
            tid=_new_id(); stamp=now()
            db.execute('INSERT INTO collab_tasks VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (tid,wid,body.project_id,body.title.strip(),body.description,body.priority,'open',who['id'],stamp,stamp))
            event(db,wid,who,'task_created',tid,{'priority':body.priority})
        return {'id':tid,'status':'open'}

    @router.post('/workspaces/{wid}/tasks/{tid}/status')
    def task_status(wid:str,tid:str,body:TaskStatus,request:Request):
        who=actor(request)
        allowed={'open':{'in_progress','blocked','cancelled'},
                 'in_progress':{'blocked','done','cancelled'},
                 'blocked':{'in_progress','cancelled'}}
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            member(db,wid,who,'editor')
            current=db.execute('SELECT status FROM collab_tasks WHERE workspace_id=? AND id=?',(wid,tid)).fetchone()
            if not current:raise HTTPException(404,'Task not found')
            if body.status not in allowed.get(current['status'],set()):raise HTTPException(409,'Invalid transition')
            db.execute('UPDATE collab_tasks SET status=?,updated_at=? WHERE id=?', (body.status,now(),tid))
            event(db,wid,who,'task_status_changed',tid,{'from':current['status'],'to':body.status,'note':body.note})
        return {'id':tid,'status':body.status}

    @router.get('/workspaces/{wid}/discussions')
    def discussions(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT d.id,d.actor_id,d.body,d.created_at,
                COALESCE(u.display_name,'Workspace owner') as actor_name
                FROM team_discussions d LEFT JOIN team_users u ON u.id=d.actor_id
                WHERE workspace_id=? ORDER BY d.created_at DESC LIMIT 100''',(wid,))]

    @router.post('/workspaces/{wid}/discussions',status_code=201)
    def post_message(wid:str,body:Note,request:Request):
        who=actor(request)
        note=body.body.strip()
        if not note:raise HTTPException(422,'Message required')
        with connection() as db:
            member(db,wid,who,'editor')
            mid=_new_id()
            db.execute('INSERT INTO team_discussions VALUES(?,?,?,?,?)',(mid,wid,who['id'],note,now()))
            event(db,wid,who,'discussion_posted',mid,{})
        return {'id':mid,'saved':True}

    class RichMessage(BaseModel):
        body:str=Field(default='',max_length=4000)
        file_ids:list[str]=Field(default_factory=list,max_length=20)

    @router.get('/workspaces/{wid}/chat')
    def get_chat(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            messages=[dict(r) for r in db.execute("""SELECT d.id,d.actor_id,d.body,d.created_at,
                COALESCE(u.display_name,'Workspace owner') actor_name
                FROM team_discussions d LEFT JOIN team_users u ON u.id=d.actor_id
                WHERE d.workspace_id=? ORDER BY d.created_at DESC LIMIT 150""",(wid,))]
            result=[]
            for msg in reversed(messages):
                msg['attachments']=[dict(r) for r in db.execute("""SELECT a.file_id,a.project_id,f.filename,f.mime,f.size
                    FROM team_message_attachments a JOIN files f ON f.id=a.file_id AND f.project_id=a.project_id
                    JOIN collab_project_links l ON l.project_id=a.project_id AND l.workspace_id=a.workspace_id
                    WHERE a.workspace_id=? AND a.message_id=? ORDER BY f.created_at""",(wid,msg['id']))]
                result.append(msg)
            return result

    @router.post('/workspaces/{wid}/chat',status_code=201)
    def post_chat(wid:str,body:RichMessage,request:Request):
        who=actor(request)
        note=body.body.strip()
        if not note and not body.file_ids:raise HTTPException(422,'Type a message or attach a file')
        if len(body.file_ids)!=len(set(body.file_ids)):raise HTTPException(422,'Duplicate attachments')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            member(db,wid,who,'editor')
            attachments=[]
            for fid in body.file_ids:
                file=db.execute("""SELECT f.id,f.project_id FROM files f
                    JOIN collab_project_links l ON l.project_id=f.project_id
                    WHERE f.id=? AND l.workspace_id=?""",(fid,wid)).fetchone()
                if not file:raise HTTPException(403,'Attachment is not part of this workspace')
                attachments.append(dict(file))
            mid=_new_id()
            db.execute('INSERT INTO team_discussions VALUES(?,?,?,?,?)',(mid,wid,who['id'],note,now()))
            for f in attachments:
                db.execute('INSERT INTO team_message_attachments VALUES(?,?,?,?)',
                           (mid,wid,f['project_id'],f['id']))
            event(db,wid,who,'discussion_posted',mid,{'attachment_count':len(attachments)})
        return {'id':mid,'saved':True,'attachments':len(attachments)}

    @router.get('/workspaces/{wid}/chat/media/{fid}')
    def play_chat_media(wid:str,fid:str,request:Request):
        who=actor(request)
        allowed={'image/jpeg','image/png','image/gif','image/webp',
                 'audio/webm','audio/ogg','audio/mp4','audio/mpeg','audio/wav','audio/x-wav',
                 'video/mp4','video/webm','application/pdf'}
        with connection() as db:
            member(db,wid,who)
            f=db.execute("""SELECT f.* FROM files f JOIN collab_project_links l
               ON f.project_id=l.project_id WHERE f.id=? AND l.workspace_id=?""",(fid,wid)).fetchone()
        if not f:raise HTTPException(404,'Attachment not found')
        mime=f['mime'].split(';')[0].strip().lower()
        if mime not in allowed:raise HTTPException(415,'Preview unavailable for this file type')
        actual=Path(f['storage_path']).resolve();root=Path(storage).resolve()
        if actual.parent!=root or actual.name!=fid or not actual.is_file():
            raise HTTPException(409,'Unsafe or missing file')
        digest=hashlib.sha256()
        with actual.open('rb') as content:
            for chunk in iter(lambda:content.read(1024*1024),b''):digest.update(chunk)
        if digest.hexdigest()!=f['sha256']:raise HTTPException(409,'File integrity failed')
        return FileResponse(actual,filename=Path(f['filename']).name,
            media_type=mime,content_disposition_type='inline',
            headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @router.post('/workspaces/{wid}/chat/upload',status_code=201)
    async def upload_chat_file(wid:str,request:Request,file:UploadFile=File(...)):
        who=actor(request)
        with connection() as db:
            member(db,wid,who,'editor')
            p=db.execute("""SELECT project_id FROM collab_project_links WHERE workspace_id=?
              ORDER BY linked_at LIMIT 1""",(wid,)).fetchone()
            if not p:
                # A private project linked to this workspace stores chat attachments.
                # All access still passes through membership and workspace permissions.
                pid=_new_id()
                stamp=now()
                db.execute('INSERT INTO projects VALUES(?,?,?)',(pid,'Workspace attachments',stamp))
                db.execute('INSERT INTO collab_project_links VALUES(?,?,?)',(pid,wid,stamp))
                event(db,wid,who,'project_created',pid,{'reason':'chat_attachment_storage'})
            else:
                pid=p['project_id']
        raw=(file.filename or '').replace('\\','/')
        name=Path(raw).name.strip()
        if not name or len(name)>180:raise HTTPException(422,'Invalid filename')
        fid=_new_id();destination=Path(storage)/fid;digest=hashlib.sha256();total=0
        try:
            with destination.open('xb') as out:
                while True:
                    chunk=await file.read(1024*1024)
                    if not chunk:break
                    total+=len(chunk)
                    if total>25*1024*1024:raise HTTPException(413,'Workspace attachments are limited to 25 MB per file')
                    digest.update(chunk);out.write(chunk)
            with connection() as db:
                db.execute('BEGIN IMMEDIATE')
                member(db,wid,who,'editor')
                if not db.execute('SELECT 1 FROM collab_project_links WHERE workspace_id=? AND project_id=?',(wid,pid)).fetchone():
                    raise HTTPException(409,'Workspace project changed during upload')
                db.execute('INSERT INTO files VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (fid,pid,name,file.content_type or 'application/octet-stream',total,digest.hexdigest(),
                     str(destination.resolve()),'','stored_not_processed',now()))
                event(db,wid,who,'file_uploaded',fid,{'project_id':pid,'filename':name,'bytes':total})
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        finally:await file.close()
        return {'id':fid,'project_id':pid,'filename':name,'mime':file.content_type or 'application/octet-stream','size':total}

    @router.get('/workspaces/{wid}/activity')
    def activity(wid:str,request:Request):
        who=actor(request)
        with connection() as db:
            member(db,wid,who)
            return [dict(r) for r in db.execute('''SELECT id,actor,event_type,object_id,created_at FROM collab_events
                         WHERE workspace_id=? ORDER BY created_at DESC LIMIT 100''',(wid,))]

    from app.team_intelligence import register_intelligence
    register_intelligence(router,connection,now,actor,member,event)
    from app.team_orchestration import register_orchestration
    register_orchestration(router,connection,now,actor,member,event)
    from app.team_actions import register_team_actions
    register_team_actions(router,connection,now,actor,member,event,storage)
    from app.team_repo_revisions import register_team_repo_revisions
    register_team_repo_revisions(router,connection,now,actor,member,event,storage)
    from app.team_execution import register_team_execution
    register_team_execution(router,connection,now,actor,member,event,storage)
    from app.team_worker_handoff import register_worker_handoff
    register_worker_handoff(router,connection,now,actor,member,event,storage)
    from app.team_unified_intelligence import register_unified_intelligence
    register_unified_intelligence(router,connection,now,actor,member,event,storage)
    from app.team_brief_collaboration import register_brief_collaboration
    register_brief_collaboration(router,connection,now,actor,member,event,storage)
    from app.team_engineering_dossier import register_engineering_dossier
    register_engineering_dossier(router,connection,now,actor,member,event,storage)
    from app.team_meta_model_lab import register_meta_model_lab
    register_meta_model_lab(router,connection,now,actor,member,event,storage)
    from app.team_advanced_synthesis import register_advanced_synthesis
    register_advanced_synthesis(router,connection,now,actor,member,event,storage)
    from app.library_vault import register_library
    register_library(router,connection,now,actor,member,event,storage)
    from app.voice_intelligence import register_voice
    async def voice_reasoner(system,turns):
        import os
        from app.main import provider_config, run_ness_model
        chosen=os.getenv('MEETING_REASONING_PROVIDER','meta').strip().lower()
        if chosen=='meta':
            provider='meta'
            key=(os.getenv('META_API_KEY') or os.getenv('MODEL_API_KEY') or '').strip()
            base='https://api.meta.ai/v1'
            model=os.getenv('MEETING_REASONING_MODEL','muse-spark-1.3').strip()
        elif chosen=='groq':
            provider='groq'
            key=os.getenv('GROQ_API_KEY','').strip()
            base='https://api.groq.com/openai/v1'
            model=os.getenv('GROQ_MODEL','openai/gpt-oss-120b').strip()
        elif chosen=='default':
            provider,key,base,model=provider_config()
        else:raise HTTPException(422,'Unknown meeting reasoning provider')
        if not key or not model:raise HTTPException(503,'Configure the selected AI reasoning provider in .env')
        answer=await run_ness_model(provider,key,base,model,system,turns)
        return answer,provider,model
    register_voice(app,router,connection,now,owner_auth,actor,member,storage,voice_reasoner)
    from app.meetings import register_meetings
    register_meetings(app, connection, actor, member)
    app.include_router(router)
    app.add_api_route('/team/library',lambda:HTMLResponse((Path(__file__).parent/'static'/'library.html').read_text(encoding='utf-8'),headers={'Cache-Control':'no-store'}),methods=['GET'])
    app.add_api_route('/team',lambda:HTMLResponse((Path(__file__).parent/'static'/'studio.html').read_text(encoding='utf-8'),headers={'Cache-Control':'no-store'}),methods=['GET'],include_in_schema=False)
    app.add_api_route('/team/classic',lambda:HTMLResponse(TEAM_HTML,headers={'Cache-Control':'no-store'}),methods=['GET'],include_in_schema=False)
    app.add_api_route('/team/login',lambda:HTMLResponse((Path(__file__).parent/'static'/'studio-login.html').read_text(encoding='utf-8'),headers={'Cache-Control':'no-store'}),methods=['GET'],include_in_schema=False)

LOGIN_HTML='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VERYNTH Ã‚Â· Team sign-in</title><style>body{font:16px system-ui;background:#f4faf9;color:#163b40;display:grid;place-items:center;min-height:95vh}main{width:min(440px,90%);background:white;padding:28px;border-radius:20px;box-shadow:0 8px 34px #2343}input,button{width:100%;padding:11px;margin:8px 0;box-sizing:border-box;border:1px solid #bcd5d3;border-radius:8px}button{background:#087f83;color:white;cursor:pointer}</style></head><body><main><h1>Ã¢Å“Â¦ VERYNTH Team</h1><p>Sign in using your invited team account.</p><form id="login"><input id="email" type="email" placeholder="Email" required><input id="password" type="password" placeholder="Password" required><button>Sign in</button><p id="error" role="alert"></p></form><details><summary>Accept a workspace invitation</summary><form id="accept"><input id="code" placeholder="Invitation code" required><input id="display" placeholder="Your name" required><input id="newpassword" type="password" minlength="12" placeholder="Choose a password (12+ characters)" required><button>Join workspace</button><p id="accepted" role="status"></p></form></details></main><script>document.getElementById('login').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/team/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:document.getElementById('email').value,password:document.getElementById('password').value})});if(r.ok)location.href='/team';else document.getElementById('error').textContent='Sign in failed';};document.getElementById('accept').onsubmit=async e=>{e.preventDefault();const r=await fetch('/api/team/auth/invitations/accept',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('code').value,display_name:document.getElementById('display').value,password:document.getElementById('newpassword').value})});document.getElementById('accepted').textContent=r.ok?'Invitation accepted. Sign in above.':'Invitation invalid or account credentials incorrect.';};</script>
<script>
(()=>{
const g=id=>document.getElementById(id), root=()=>'/workspaces/'+wid+'/brief-collaboration';
const message=s=>{g('briefTeamStatus').textContent=s};
let snapshot=null;
const selected=()=>g('briefTeamSelect').value;
async function load(){if(!wid)return;try{const all=await req('/workspaces/'+wid+'/unified/briefs');const menu=g('briefTeamSelect');const previous=menu.value;menu.replaceChildren();for(const b of all){const o=document.createElement('option');o.value=b.id;o.textContent=b.title+' Ã‚Â· '+b.id.slice(0,8);menu.append(o)}if(all.some(b=>b.id===previous))menu.value=previous;message(all.length?all.length+' saved briefs available':'No saved briefs. Create one in Unified Investigation Brief.');}catch(e){message(e.message)}}
async function open(){if(!selected())return;try{const b=await req(root()+'/'+selected());snapshot=b;const out=g('briefTeamView');out.replaceChildren();const heading=document.createElement('p');heading.textContent='Review: '+b.review_state+' Ã‚Â· Source freshness: '+(b.matches_current_evidence?'current':'STALE')+' Ã‚Â· '+b.comments.length+' comments Ã‚Â· '+b.followups.length+' follow-ups';out.append(heading);for(const c of b.comments){const p=document.createElement('p');p.textContent='Comment ['+c.actor_id.slice(0,8)+']: '+c.body+(c.source_file_id?' Ã‚Â· evidence '+c.source_file_id.slice(0,8):'');out.append(p)}for(const t of b.followups){const p=document.createElement('p');p.textContent='Follow-up '+t.title+' ['+t.status+'] Ã‚Â· '+t.priority+(t.assigned_to?' Ã‚Â· assigned '+t.assigned_to.slice(0,8):'');out.append(p)}for(const r of b.reviews){const p=document.createElement('p');p.textContent='Human decision: '+r.decision+' Ã¢â‚¬â€ '+r.rationale;out.append(p)}const detail=await req('/workspaces/'+wid+'/unified/briefs/'+selected());const sources=g('briefTeamSource');sources.replaceChildren();const blank=document.createElement('option');blank.value='';blank.textContent='General discussion';sources.append(blank);for(const source of detail.snapshot.sources){const o=document.createElement('option');o.value=source.id;o.textContent=source.filename;sources.append(o)}message('Loaded human review of saved historical brief.');}catch(e){message(e.message)}}
g('briefTeamLoad').onclick=load;g('briefTeamOpen').onclick=open;
g('briefTeamComment').onsubmit=async e=>{e.preventDefault();if(!selected())return;try{await req(root()+'/'+selected()+'/comments',{body:g('briefTeamBody').value,source_file_id:g('briefTeamSource').value||null});g('briefTeamBody').value='';await open()}catch(err){message(err.message)}};
g('briefTeamTask').onsubmit=async e=>{e.preventDefault();if(!selected())return;try{await req(root()+'/'+selected()+'/followups',{title:g('briefTeamTaskTitle').value,description:g('briefTeamTaskText').value,priority:g('briefTeamPriority').value});g('briefTeamTaskTitle').value='';g('briefTeamTaskText').value='';await open()}catch(err){message(err.message)}};
g('briefTeamReview').onsubmit=async e=>{e.preventDefault();if(!selected())return;try{await req(root()+'/'+selected()+'/reviews',{decision:g('briefTeamDecision').value,rationale:g('briefTeamRationale').value});g('briefTeamRationale').value='';await open()}catch(err){message(err.message)}};
})();
</script><script>
(()=>{
const $=id=>document.getElementById(id);
// Workspace ID is read from the existing workspace picker, rather than creating a separate login.
// Existing team's JS stores selection in lexical state; discover from workspace selector in its event handler when available.
const call=async(path,opt)=>{const w=wid;if(!w)throw Error('Select a workspace first; if this panel cannot read selection, use the existing collaboration panel.');const r=await fetch('/api/team/workspaces/'+encodeURIComponent(w)+path,{credentials:'same-origin',headers:{'Content-Type':'application/json'},...opt});const d=await r.json();if(!r.ok)throw Error(d.detail||'Request failed');return d};
let chosen='';const report=(v)=>JSON.stringify(v,null,2);
async function refresh(){const items=await call('/investigations');const pick=$('engInvestigation');pick.replaceChildren();for(const it of items){const o=document.createElement('option');o.value=it.id;o.textContent=it.question||it.id;pick.append(o)}const dossiers=await call('/engineering/dossiers');$('engDossier').replaceChildren();for(const d of dossiers){const o=document.createElement('option');o.value=d.id;o.textContent=d.title;$('engDossier').append(o)}}
async function handler(fn){try{await fn();$('engStatus').textContent='Ready'}catch(e){$('engStatus').textContent=e.message}}
$('engRefresh').addEventListener('click',()=>handler(refresh));
$('engPreview').addEventListener('click',()=>handler(async()=>{$('engPreviewOutput').textContent=report(await call('/engineering/preview/'+encodeURIComponent($('engInvestigation').value)))}));
$('engSave').addEventListener('submit',e=>{e.preventDefault();handler(async()=>{const d=await call('/engineering/dossiers',{method:'POST',body:JSON.stringify({investigation_id:$('engInvestigation').value,title:$('engTitle').value,interpretation:$('engInterpretation').value})});chosen=d.id;await refresh();$('engDossier').value=d.id;$('engStatus').textContent='Saved dossier '+d.id})});
$('engOpen').addEventListener('click',()=>handler(async()=>{chosen=$('engDossier').value;$('engDetail').textContent=report(await call('/engineering/dossiers/'+encodeURIComponent(chosen)))}));
$('engRecover').addEventListener('submit',e=>{e.preventDefault();handler(async()=>{if(!chosen)throw Error('Open a saved dossier first');const d=await call('/engineering/dossiers/'+encodeURIComponent(chosen)+'/recovery',{method:'POST',body:JSON.stringify({title:$('engTaskTitle').value,rationale:$('engTaskReason').value,priority:$('engPriority').value})});$('engDetail').textContent='Recovery task created: '+d.task_id+' (not executed)'})});
})();
</script></body></html>'''

TEAM_HTML='''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>VERYNTH Ã‚Â· Workspaces</title><style>:root{font:15px system-ui;color:#173d42;background:#f5faf9}*{box-sizing:border-box}body{margin:0}header{background:white;padding:20px max(20px,calc((100vw - 1100px)/2));border-bottom:1px solid #dcebe8}h1{margin:0;font-size:25px}main{max-width:1100px;margin:30px auto;padding:0 20px;display:grid;grid-template-columns:220px 1fr;gap:22px}.card{background:white;border:1px solid #dcebe8;border-radius:15px;padding:20px;margin-bottom:16px}button,input,select,textarea{font:inherit;border:1px solid #bed6d2;padding:10px;border-radius:9px;max-width:100%}button{cursor:pointer;background:#087f83;color:white;border:0}button:disabled{opacity:.5}input{width:100%}section{min-width:0}ul{padding-left:20px}li{margin:8px 0}small{color:#668285}pre{white-space:pre-wrap}#error{color:#a43636}a{color:#087f83}@media(max-width:700px){main{grid-template-columns:1fr}}</style><style>
/* VERYNTH collaborative design polish. No behavioral changes. */
:root{color:#193746;background:#f4f8f8}body{background:radial-gradient(circle at 90% -10%,#daf3f0,transparent 45%),#f5f8f9}header{background:linear-gradient(115deg,#073640,#0b5660);color:white;border-bottom:0;padding-block:24px;box-shadow:0 8px 28px #062f3d18}header h1{letter-spacing:.11em;font-size:23px}header small{color:#c6e7e5}main{max-width:1320px;grid-template-columns:235px minmax(0,1fr);gap:25px;margin-top:26px}main>aside{position:sticky;top:15px;align-self:start}.card{background:#fff;border:1px solid #dce8e7;border-radius:19px;box-shadow:0 10px 36px #0a43500a;padding:23px;margin-bottom:18px}.card h2,.card h3{letter-spacing:-.02em;color:#193c47}.card details{max-width:100%}.card summary{cursor:pointer;padding:6px 2px;color:#164e58}.card details[open]>summary{margin-bottom:12px}.card:has(details:not([open])){padding:15px 22px}.card:has(details:not([open])):hover{border-color:#8ac8c3;background:#fcfefe}button{background:linear-gradient(130deg,#0b8d8c,#096d7d);box-shadow:0 3px 10px #073d4211}button:hover{filter:brightness(1.08)}button:focus-visible,summary:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible,a:focus-visible{outline:3px solid #12bdb1;outline-offset:2px}pre{background:#f5f9f9;border-radius:12px;padding:12px;overflow:auto;max-width:100%}small{line-height:1.5}@media(max-width:800px){main{grid-template-columns:1fr}main>aside{position:static}header{padding:18px}}
</style><style>.verynth-back,.verynth-library-link{display:inline-block;text-decoration:none!important;margin:0 12px 12px 0;padding:9px 15px;border:1px solid #40a99e;border-radius:12px;background:#0a4549;color:#e4ffff!important;font-weight:600}.verynth-back:hover,.verynth-library-link:hover{background:#0d7274}details.card{background:#f7fbfa}details:not([open])>*:not(summary){display:none}</style><link rel="stylesheet" href="/static/verynth-focus.css"></head><body><header><a class="verynth-back" href="/" title="Back to personal workspace">Ã¢â€ Â Back</a><a class="verynth-library-link" href="/team/library">Ã¢â€“Â£ Library</a><h1>Ã¢Å“Â¦ VERYNTH <small>Workspaces</small></h1><small>Individual intelligence Ã‚Â· Collaborative teamwork</small></header><main><aside class="card"><h3>Your workspaces</h3><div id="workspaces"></div><form id="createWorkspace" hidden><input id="workspaceName" placeholder="New team workspace" required><button>Create workspace</button></form><p><a href="/">Personal VERYNTH (owner)</a></p></aside><section><div id="error" role="alert"></div><div class="card"><h2 id="title">Choose a workspace</h2><p id="role"></p></div><div class="card"><details><summary><strong>Live meetings Ã‚Â· Preview</strong></summary><p><small>Start a private workspace meeting. Participants must be signed in and members of this workspace. Recording is off. WebRTC across different networks may require a TURN server.</small></p><button type="button" id="meetingCreate">Create live meeting</button><p id="meetingLink"></p></details></div><div class="card"><h3>Projects & evidence</h3><form id="projectform" hidden><input id="projectName" placeholder="New shared project" required><button>Create project</button></form><div id="projects"></div></div><div class="card"><h3>Team tasks</h3><form id="taskform"><input id="task" placeholder="New task" required><button>Create task</button></form><div id="tasks"></div></div><div class="card"><h3>Discussion</h3><form id="messageform"><textarea id="message" placeholder="Share an update" required></textarea><button>Post update</button></form><div id="discussion"></div></div><div class="card"><h3>Membership & invitations</h3><div id="members"></div><form id="inviteform"><input id="invite_email" type="email" placeholder="Teammate email" required><select id="invite_role"><option>editor</option><option>viewer</option><option>admin</option></select><button>Create invitation</button></form><p id="invite_code"></p></div><div class="card"><h3>Collaborative Intelligence</h3><small>Shared investigations, Ness reviews, assignments and controlled decisions. No autonomous execution.</small><form id="investigateform"><select id="investigateproject" required aria-label="Shared project"></select><label for="investigatesources">Evidence files (optional; Ctrl-click to select multiple)</label><select id="investigatesources" multiple aria-label="Evidence sources" style="width:100%;min-height:65px"></select><textarea id="investigatequestion" placeholder="What should the team investigate?" minlength="10" required></textarea><button>Create investigation</button></form><div id="investigations"></div><div id="investigationreview" aria-live="polite"></div><h3>Human approvals</h3><div id="approvals"></div><form id="approvalform"><select id="approvalinvestigation" required aria-label="Investigation"></select><textarea id="approvalaction" placeholder="Action requiring approval" minlength="8" required></textarea><textarea id="approvalreason" placeholder="Reason and scope" minlength="8" required></textarea><button>Request human approval</button></form><h3>Task assignments</h3><div id="assignments"></div><details class="card"><summary><strong>Ness Ã‚Â· Task Orchestration</strong></summary><small>Real saved plans, supported capability routing, human-recorded evidence. Execution tools are not connected.</small><form id="orchform"><select id="orchinvestigation" required aria-label="Investigation to plan"></select><button>Plan investigation steps</button></form><div id="orchplans" role="status"></div><div id="orchdetail"></div></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Verified File Tools</strong></summary><p><small>Real, bounded multidisciplinary and repository ZIP inspection. Results are evidence-bound and separately approved. Keyword screening is not diagnosis; arbitrary code execution is unavailable.</small></p><button id="safeRefresh" type="button">Load files and actions</button><form id="safePropose"><label>Project</label><select id="safeProject" required></select><label>Source file</label><select id="safeFile" required></select><label>Tool</label><select id="safeTool"><option value="file.sha256">Verify SHA-256</option><option value="text.profile">Text profile</option><option value="json.validate">JSON validation</option><option value="csv.profile">CSV profile</option><option value="csv.numeric_stats">CSV numeric statistics</option><optgroup label="Multidisciplinary analysis"><option value="evidence.detect_context">Recognize evidence context (content-based)</option><option value="csv.data_quality">CSV missing values and duplicates</option><option value="csv.correlation">CSV Pearson correlation</option><option value="csv.linear_model">CSV least-squares line</option><option value="csv.finance_summary">CSV financial arithmetic</option><option value="csv.group_summary">CSV grouped statistics</option><option value="json.numeric_summary">JSON numeric summary</option><option value="text.security_indicators">Source code security indicator screening</option><option value="text.research_signals">Research methodology terminology</option></optgroup><optgroup label="Repository ZIP Ã‚Â· static inspection"><option value="repo.manifest">Archive manifest and file hashes</option><option value="repo.python_syntax">Python syntax (AST only)</option><option value="repo.dependencies">Declared dependency inventory</option><option value="repo.test_discovery">Identify tests (does not run)</option><option value="repo.security_signals">Python security review signals</option><option value="repo.import_graph">Python static import graph</option><option value="repo.python_metrics">Python AST metrics</option></optgroup></select><input id="safeColumn" placeholder="First column / JSON key (when required)"><input id="safeColumnB" placeholder="Second column (when required)"><textarea id="safeReason" placeholder="Why is this check needed? (12+ characters)" required minlength="12"></textarea><button>Propose read-only action</button></form><h4>Workspace actions</h4><div id="safeActions"></div><input type="hidden" id="safeSelected"><label>Independent reviewer decision</label><select id="safeDecision"><option value="approve">Approve</option><option value="reject">Reject</option></select><textarea id="safeReviewReason" placeholder="Reviewer rationale (12+ characters)" minlength="12"></textarea><button id="safeReview" type="button">Record review</button><button id="safeExecute" type="button">Run approved tool</button><div id="safeStatus" role="status" aria-live="polite"></div><div id="safeDetail"></div><details><summary>Link verified tool result to an investigation plan</summary><p><small>Only successful actions linked to the same investigation and source can be attached. Linking does not complete the step.</small></p><label>Plan</label><select id="safePlan"></select><label>Plan step</label><select id="safeStep"></select><button id="safeLink" type="button">Link verified result</button></details></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Repository Revision Studio</strong></summary><p><small>Controlled, versioned ZIP text changes. Independent approval, immutable original, AST syntax checks and stored artifact verification. Repository tests are not run; isolated execution is not connected.</small></p><button type="button" id="revRefresh">Load repository revisions</button><form id="revPropose"><label>Source project / ZIP (from Verified File Tools)</label><p><small>Use the project and file selected in Verified File Tools above.</small></p><label>Existing path in ZIP</label><input id="revTarget" placeholder="src/math_service.py" required maxlength="240"><label>Exact old text (must appear once)</label><textarea id="revOld" required maxlength="8192" placeholder="return x - y"></textarea><label>Replacement text</label><textarea id="revNew" maxlength="8192" placeholder="return x + y"></textarea><label>Engineering rationale</label><textarea id="revReason" required minlength="12" maxlength="2000"></textarea><button>Propose reviewable revision</button></form><div id="revHistory"></div><div id="revDetail" role="status"></div><label>Reviewer decision</label><select id="revDecision"><option value="approve">Approve</option><option value="reject">Reject</option></select><textarea id="revRationale" placeholder="Independent review rationale (12+ characters)" minlength="12"></textarea><button type="button" id="revReview">Record decision</button><button type="button" id="revStage">Stage approved ZIP version</button><div id="revStatus" role="status" aria-live="polite"></div></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Isolated Execution Requests</strong></summary><p><small>Prepare approved repository test requests and immutable worker manifests. No isolated worker connected; repository code cannot execute.</small></p><button id="exeRefresh" type="button">Load staged revisions & requests</button><form id="exePropose"><label>Staged revision</label><select id="exeRevision" required></select><label>Test framework</label><select id="exeSelector"><option value="pytest">pytest</option><option value="unittest">unittest</option></select><textarea id="exeReason" minlength="12" required placeholder="Why is this test needed?"></textarea><button>Request isolated test run</button></form><div id="exeHistory"></div><p id="exeStatus" role="status" aria-live="polite"></p></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· External Worker Handoffs</strong></summary><p><small>External report exchange is disabled until a trusted isolated worker is separately configured. An authenticated report is not proof of sandbox isolation or independently verified tests.</small></p><button type="button" id="workerRefresh">Inspect handoff status</button><div id="workerStatus" role="status" aria-live="polite"></div><div id="workerHistory"></div></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Unified Investigation Brief</strong></summary><p><small>Evidence-grounded views of saved investigations, AI reviews, tools and plans. Model answers are not independently verified. No code executes here.</small></p><button type="button" id="unifiedLoad">Load investigations and briefs</button><label>Investigation</label><select id="unifiedInvestigation"></select><button type="button" id="unifiedPreview">Preview provenance and gaps</button><button type="button" id="unifiedNessReview">Ask Ness for a real model review</button><p id="unifiedStatus" role="status"></p><pre id="unifiedPreviewText" style="white-space:pre-wrap;max-height:24rem;overflow:auto"></pre><form id="unifiedSave"><input id="unifiedTitle" required minlength="5" maxlength="150" placeholder="Brief title"><textarea id="unifiedInterpretation" maxlength="4000" placeholder="Optional human interpretation"></textarea><textarea id="unifiedLimitations" maxlength="3000" placeholder="Optional limitations"></textarea><button>Save evidence-bound brief</button></form><h4>Saved briefs</h4><div id="unifiedHistory"></div></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Team Review & Follow-ups</strong></summary><p><small>Human review of saved, fingerprinted investigation briefs. Comments link to real source files. Follow-ups are workspace tasks. Acceptance is not scientific certification.</small></p><button type="button" id="briefTeamLoad">Load saved briefs</button><label>Saved investigation brief</label><select id="briefTeamSelect"></select><button type="button" id="briefTeamOpen">Open team review</button><div id="briefTeamStatus" role="status"></div><div id="briefTeamView"></div><form id="briefTeamComment"><label>Comment</label><textarea id="briefTeamBody" minlength="5" maxlength="3000" required placeholder="Review finding or concern"></textarea><label>Optional evidence source</label><select id="briefTeamSource"><option value="">General discussion</option></select><button>Add evidence-linked comment</button></form><form id="briefTeamTask"><label>Follow-up task</label><input id="briefTeamTaskTitle" required minlength="6" maxlength="180" placeholder="Action required"><textarea id="briefTeamTaskText" required minlength="10" maxlength="2000" placeholder="What should be checked and why?"></textarea><label>Priority</label><select id="briefTeamPriority"><option>normal</option><option>high</option><option>urgent</option><option>low</option></select><button>Create linked team task</button></form><form id="briefTeamReview"><label>Independent admin decision</label><select id="briefTeamDecision"><option value="changes_requested">Request changes</option><option value="accept_for_demo">Accept for demo (human review only)</option></select><textarea id="briefTeamRationale" required minlength="12" maxlength="2500" placeholder="Reasoned independent review"></textarea><button>Record review</button></form></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Engineering Evidence & Recovery</strong></summary><p><small>Connect actual saved repository revisions, approved execution requests, worker-report records and project simulations. Simulations are calculations, not repository tests. No execution occurs here.</small></p><button id="engRefresh" type="button">Load engineering evidence</button><label>Investigation</label><select id="engInvestigation"></select><button id="engPreview" type="button">Preview evidence chain</button><pre id="engPreviewOutput" style="max-height:22rem;overflow:auto;white-space:pre-wrap"></pre><form id="engSave"><input id="engTitle" required minlength="6" maxlength="150" placeholder="Engineering dossier title"><textarea id="engInterpretation" maxlength="3000" placeholder="Human interpretation (optional)"></textarea><button>Save evidence dossier</button></form><label>Saved dossier</label><select id="engDossier"></select><button id="engOpen" type="button">Open saved dossier</button><div id="engStatus" role="status"></div><pre id="engDetail" style="max-height:24rem;overflow:auto;white-space:pre-wrap"></pre><form id="engRecover"><input id="engTaskTitle" required minlength="6" maxlength="180" placeholder="Follow-up task title"><textarea id="engTaskReason" required minlength="12" maxlength="2500" placeholder="What needs investigation or recovery?"></textarea><select id="engPriority"><option>high</option><option>urgent</option><option>normal</option><option>low</option></select><button>Create human recovery task</button></form></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Meta Model Lab</strong></summary><p><small>Actual Meta API model probes and evidence-grounded comparisons. Image and SAM model output unavailable until integrated. Model responses are not independent verification.</small></p><button type="button" id="metaCatalog">Check model catalog</button><pre id="metaCatalogOut" style="white-space:pre-wrap;max-height:14rem;overflow:auto"></pre><label>Live probe (owner only)</label><select id="metaProbe"><option>muse-spark-1.3</option><option>muse-wonder-1.0</option><option>muse-spark-1.2</option></select><button type="button" id="metaProbeRun">Run real Meta API probe</button><label>Investigation</label><select id="metaInvestigation"></select><label>Primary model</label><select id="metaModelA"><option>muse-spark-1.3</option><option>muse-wonder-1.0</option><option>muse-spark-1.2</option></select><label>Optional second model</label><select id="metaModelB"><option value="">One model only</option><option>muse-wonder-1.0</option><option>muse-spark-1.3</option><option>muse-spark-1.2</option></select><textarea id="metaQuestion" placeholder="Ask a grounded comparison question" maxlength="3000"></textarea><button type="button" id="metaCompareRun">Run and save real model analysis</button><button type="button" id="metaCompareRefresh">Load saved comparisons</button><select id="metaComparison"></select><button type="button" id="metaComparisonOpen">Open saved comparison</button><pre id="metaOutput" style="white-space:pre-wrap;max-height:30rem;overflow:auto"></pre></details></div><div class="card"><details><summary><strong>Ness Ã‚Â· Advanced Intelligence Synthesis</strong></summary><p><small>Evidence-linked Muse comparisons, model perspectives, saved Reality Twin simulations, and Afterlight-style freshness checks. This summary does not run models or certify findings.</small></p><button id="advancedLoad" type="button">Load investigations</button><label>Investigation</label><select id="advancedInvestigation"></select><button type="button" id="advancedPreview">Preview connected intelligence</button><form id="advancedSave"><input id="advancedTitle" minlength="6" maxlength="150" placeholder="Synthesis title" required><textarea id="advancedAssessment" maxlength="3000" placeholder="Human assessment (optional)"></textarea><button>Save intelligence synthesis</button></form><button type="button" id="advancedList">Load saved syntheses</button><select id="advancedSaved"></select><button type="button" id="advancedOpen">Check saved synthesis &amp; freshness</button><pre id="advancedOutput" role="status" style="white-space:pre-wrap;max-height:28rem;overflow:auto"></pre></details></div><div class="card"><h3>Recent activity</h3><div id="activity"></div></div></section></main><script>
async function loadOrchestration(){if(!wid)return;try{const investigations=await req('/workspaces/'+wid+'/investigations');const pick=$('orchinvestigation');pick.replaceChildren();investigations.forEach(i=>{const op=document.createElement('option');op.value=i.id;op.textContent=i.question.slice(0,120);pick.append(op)});const plans=await req('/workspaces/'+wid+'/orchestration/plans');const list=$('orchplans');list.replaceChildren();plans.forEach(p=>{const b=document.createElement('button');b.type='button';b.textContent='Plan Ã‚Â· '+p.goal.slice(0,70)+' ('+p.status+')';b.style.margin='4px';b.onclick=()=>viewOrchestration(p.id);list.append(b)});if(!plans.length)line(list,'No plans yet.')}catch(e){$('error').textContent=e.message}}
async function viewOrchestration(pid){try{const info=await req('/workspaces/'+wid+'/orchestration/plans/'+pid),root=$('orchdetail');root.replaceChildren();line(root,'Context: '+info.plan.domains.map(x=>x.domain).join(', ')+' Ã‚Â· fingerprint '+info.plan.source_fingerprint.slice(0,16)+'Ã¢â‚¬Â¦');info.steps.forEach(s=>{const wrap=document.createElement('div');wrap.style.cssText='border-top:1px solid #ddd;padding:12px 0';line(wrap,(s.position+1)+'. '+s.title+' Ã‚Â· '+s.status+' Ã‚Â· '+s.capability);line(wrap,s.instructions);line(wrap,'Capability: '+s.availability+' Ã‚Â· Depends on '+(s.dependencies.length?s.dependencies.map(x=>x+1).join(', '):'none'));if(s.status==='pending'&&canEdit()){const select=document.createElement('select');['blocked','failed','completed'].forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v;select.append(o)});const input=document.createElement('input');input.placeholder='Reason / observations (required)';const evidence=document.createElement('input');evidence.placeholder='Existing evidence file IDs (comma-separated, required for completion)';const btn=document.createElement('button');btn.textContent='Record human-reviewed outcome';btn.onclick=async()=>{const ids=evidence.value.split(',').map(x=>x.trim()).filter(Boolean);try{await req('/workspaces/'+wid+'/orchestration/plans/'+pid+'/steps/'+s.id+'/record',{outcome:select.value,rationale:input.value,evidence_file_ids:ids});await viewOrchestration(pid)}catch(e){$('error').textContent=e.message}};wrap.append(select,input,evidence,btn)}root.append(wrap)})}catch(e){$('error').textContent=e.message}}
window.addEventListener('load',()=>{$('orchform').onsubmit=async e=>{e.preventDefault();try{const p=await req('/workspaces/'+wid+'/orchestration/plans',{investigation_id:$('orchinvestigation').value});await loadOrchestration();await viewOrchestration(p.id)}catch(err){$('error').textContent=err.message}};});
let wid='',role='';const $=x=>document.getElementById(x),canEdit=()=>['owner','admin','editor'].includes(role),canInvite=()=>['owner','admin'].includes(role);
const req=async(path,body)=>{const r=await fetch('/api/team'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});const data=await r.json();if(!r.ok)throw Error(data.detail||'Request failed');return data;};
function line(parent,label){const p=document.createElement('p');p.textContent=label;parent.append(p);}
async function openWorkspace(id){wid=id;$('error').textContent='';try{const data=await req('/workspaces/'+wid);role=data.role;$('title').textContent=data.name;$('role').textContent='Your role: '+role;$('taskform').hidden=!canEdit();$('messageform').hidden=!canEdit();$('inviteform').hidden=!canInvite();$('projectform').hidden=role!=='owner';await refresh();await refreshIntelligence();await loadOrchestration();}catch(e){$('error').textContent=e.message}}
async function refresh(){try{const paths=['projects','tasks','discussions','members','activity'];const results=await Promise.all(paths.map(p=>req('/workspaces/'+wid+'/'+p)));paths.forEach((name,i)=>{const el=$(name==='discussions'?'discussion':name);el.replaceChildren();results[i].forEach(x=>{let detail=name==='tasks'?x.title+' Ã‚Â· '+x.status+' Ã‚Â· '+x.priority:name==='projects'?x.name:name==='discussions'?x.actor_name+': '+x.body:name==='members'?x.display_name+' ('+x.role+')':x.event_type+' Ã‚Â· '+x.created_at;line(el,detail);if(name==='tasks'&&canEdit()){const allowed={open:['in_progress','blocked','cancelled'],in_progress:['blocked','done','cancelled'],blocked:['in_progress','cancelled']}[x.status]||[];if(allowed.length){const select=document.createElement('select');for(const state of allowed){const opt=document.createElement('option');opt.value=state;opt.textContent=state;select.append(opt)}const btn=document.createElement('button');btn.textContent='Update';btn.style.margin='4px';btn.onclick=async()=>{const note=window.prompt('Reason for status change (required):');if(!note||note.trim().length<3)return;try{await req('/workspaces/'+wid+'/tasks/'+x.id+'/status',{status:select.value,note});await refresh();}catch(err){$('error').textContent=err.message}};el.append(select,btn)}}});if(!results[i].length)line(el,'No records yet.');});for(const p of results[0]){const files=await req('/workspaces/'+wid+'/projects/'+p.id+'/files');for(const f of files){const a=document.createElement('a');a.href='/api/team/workspaces/'+encodeURIComponent(wid)+'/projects/'+encodeURIComponent(p.id)+'/files/'+encodeURIComponent(f.id)+'/download';a.textContent='Download '+f.filename;const div=document.createElement('p');div.append(a);$('projects').append(div);}if(canEdit()){const input=document.createElement('input');input.type='file';input.setAttribute('aria-label','Upload file to '+p.name);input.onchange=async()=>{if(!input.files.length)return;const data=new FormData();data.append('file',input.files[0]);const r=await fetch('/api/team/workspaces/'+encodeURIComponent(wid)+'/projects/'+encodeURIComponent(p.id)+'/files',{method:'POST',body:data});if(!r.ok){$('error').textContent='Shared upload failed';return;}input.value='';await refresh();};$('projects').append(input);}}}catch(e){$('error').textContent=e.message}}
$('projectform').onsubmit=async e=>{e.preventDefault();try{const r=await fetch('/api/collaboration/workspaces/'+encodeURIComponent(wid)+'/projects/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('projectName').value})});if(!r.ok)throw Error('Unable to create project');$('projectName').value='';await refresh();}catch(e){$('error').textContent=e.message}};
$('taskform').onsubmit=async e=>{e.preventDefault();try{await req('/workspaces/'+wid+'/tasks',{title:$('task').value});$('task').value='';await refresh()}catch(e){$('error').textContent=e.message}};
$('messageform').onsubmit=async e=>{e.preventDefault();try{await req('/workspaces/'+wid+'/discussions',{body:$('message').value});$('message').value='';await refresh()}catch(e){$('error').textContent=e.message}};
$('createWorkspace').onsubmit=async e=>{e.preventDefault();try{const r=await fetch('/api/collaboration/workspaces',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:$('workspaceName').value})});const data=await r.json();if(!r.ok)throw Error(data.detail||'Could not create workspace');location.reload();}catch(e){$('error').textContent=e.message}};
$('inviteform').onsubmit=async e=>{e.preventDefault();try{const data=await req('/workspaces/'+wid+'/invitations',{email:$('invite_email').value,role:$('invite_role').value});$('invite_code').textContent='One-time invitation code (share privately): '+data.invitation_code;}catch(e){$('error').textContent=e.message}};
(async()=>{try{const who=await req('/me');$('createWorkspace').hidden=!who.owner;const w=await req('/workspaces');$('workspaces').replaceChildren();w.forEach(x=>{const b=document.createElement('button');b.textContent=x.name+' Ã‚Â· '+x.role;b.style.margin='5px 0';b.onclick=()=>openWorkspace(x.id);$('workspaces').append(b)});if(w.length)await openWorkspace(w[0].id)}catch(e){$('error').textContent=e.message}})();
async function refreshIntelligence(){if(!wid)return;
  try{const [projects,investigations,approvals,assignments,members,tasks]=await Promise.all([
    req('/workspaces/'+wid+'/projects'),req('/workspaces/'+wid+'/investigations'),
    req('/workspaces/'+wid+'/approvals'),req('/workspaces/'+wid+'/assignments'),
    req('/workspaces/'+wid+'/members'),req('/workspaces/'+wid+'/tasks')]);
    const fill=(id,items,value,label)=>{const el=$(id);el.replaceChildren();for(const it of items){const o=document.createElement('option');o.value=it[value];o.textContent=it[label];el.append(o)}};
    fill('investigateproject',projects,'id','name');await loadTeamEvidence();fill('approvalinvestigation',investigations,'id','question');
    $('investigateform').hidden=!canEdit();$('approvalform').hidden=!canEdit();
    const panel=$('investigations');panel.replaceChildren();for(const item of investigations){const section=document.createElement('div');section.style.margin='12px 0';line(section,item.question+' Ã‚Â· '+item.status);
      const open=document.createElement('button');open.textContent='Open evidence & Ness reviews';open.onclick=async()=>{try{const data=await req('/workspaces/'+wid+'/investigations/'+item.id);const area=$('investigationreview');area.replaceChildren();line(area,'Evidence: '+(data.sources.map(x=>x.filename+' [SOURCE '+x.file_id+']').join(', ')||'None attached'));for(const review of data.ness_reviews){const pre=document.createElement('pre');pre.textContent=review.answer;area.append(pre)} }catch(e){$('error').textContent=e.message}};section.append(open);
      if(canEdit()){const run=document.createElement('button');run.textContent='Ask Ness (AI)';run.style.marginLeft='8px';run.onclick=async()=>{run.disabled=true;run.textContent='Ness is analyzingÃ¢â‚¬Â¦';try{await req('/workspaces/'+wid+'/investigations/'+item.id+'/ness-review',{});await refreshIntelligence();}catch(e){$('error').textContent=e.message}finally{run.disabled=false;run.textContent='Ask Ness (AI)'}};section.append(run)}panel.append(section)}
    const ap=$('approvals');ap.replaceChildren();for(const a of approvals){const block=document.createElement('div');block.style.margin='14px 0';line(block,a.action+' Ã‚Â· '+a.status+' Ã‚Â· '+a.reason);
      for(const d of a.decisions)line(block,'Opinion: '+d.decision+' Ã¢â‚¬â€ '+d.rationale);
      if(canEdit()&&['pending','conflicted'].includes(a.status)){for(const opinion of ['support','object']){const b=document.createElement('button');b.textContent=opinion;b.style.margin='4px';b.onclick=async()=>{const rationale=prompt('Why do you '+opinion+' this action? (8+ characters)');if(!rationale||rationale.trim().length<8)return;try{await req('/workspaces/'+wid+'/approvals/'+a.id+'/decision',{decision:opinion,rationale});await refreshIntelligence()}catch(e){$('error').textContent=e.message}};block.append(b)}}
      if(['owner','admin'].includes(role)&&['pending','conflicted'].includes(a.status)){for(const resolution of ['approve','reject']){const b=document.createElement('button');b.textContent=resolution+' review';b.style.margin='4px';b.onclick=async()=>{const rationale=prompt('Document the resolution (12+ characters)');if(!rationale||rationale.trim().length<12)return;try{await req('/workspaces/'+wid+'/approvals/'+a.id+'/resolve',{resolution,rationale});await refreshIntelligence()}catch(e){$('error').textContent=e.message}};block.append(b)}}ap.append(block)}
    const ass=$('assignments');ass.replaceChildren();for(const a of assignments)line(ass,a.title+' Ã¢â€ â€™ '+(members.find(m=>m.user_id===a.user_id)?.display_name||a.user_id));
    if(canEdit()&&tasks.length){const form=document.createElement('form');const sel=document.createElement('select');for(const task of tasks){const o=document.createElement('option');o.value=task.id;o.textContent=task.title;sel.append(o)}const user=document.createElement('select');for(const m of members){const o=document.createElement('option');o.value=m.user_id;o.textContent=m.display_name;user.append(o)}const btn=document.createElement('button');btn.textContent='Assign selected task';form.append(sel,user,btn);form.onsubmit=async e=>{e.preventDefault();try{await req('/workspaces/'+wid+'/tasks/'+sel.value+'/assignment',{user_id:user.value,note:'Assigned through the shared workspace'});await refreshIntelligence()}catch(err){$('error').textContent=err.message}};ass.append(form)}
  }catch(e){$('error').textContent=e.message}}
async function loadTeamEvidence(){const sel=$('investigatesources');sel.replaceChildren();const pid=$('investigateproject').value;if(!pid||!wid)return;try{const files=await req('/workspaces/'+wid+'/projects/'+pid+'/files');for(const f of files){const option=document.createElement('option');option.value=f.id;option.textContent=f.filename+' Ã‚Â· '+f.sha256.slice(0,10);sel.append(option)}}catch(e){$('error').textContent=e.message}}
$('investigateproject').onchange=loadTeamEvidence;
$('investigateform').onsubmit=async e=>{e.preventDefault();try{await req('/workspaces/'+wid+'/investigations',{project_id:$('investigateproject').value,question:$('investigatequestion').value,file_ids:Array.from($('investigatesources').selectedOptions,x=>x.value)});$('investigatequestion').value='';await refreshIntelligence()}catch(err){$('error').textContent=err.message}};
$('approvalform').onsubmit=async e=>{e.preventDefault();try{await req('/workspaces/'+wid+'/approvals',{investigation_id:$('approvalinvestigation').value,action:$('approvalaction').value,reason:$('approvalreason').value});$('approvalaction').value='';$('approvalreason').value='';await refreshIntelligence()}catch(err){$('error').textContent=err.message}};
</script><script>
(function(){
const el=id=>document.getElementById(id);
const set=(id,text)=>{el(id).textContent=text};
const api=(suffix,body)=>req('/workspaces/'+encodeURIComponent(wid)+'/tool-actions'+suffix,body);
const showError=e=>set('safeStatus',e.message||String(e));
function selectOptions(element,items,label){element.replaceChildren();for(const x of items){const o=document.createElement('option');o.value=x.id;o.textContent=label(x);element.append(o)}}
async function refreshFiles(){if(!wid)return;try{const projects=await req('/workspaces/'+encodeURIComponent(wid)+'/projects');selectOptions(el('safeProject'),projects,x=>x.name||x.id);await refreshProjectFiles()}catch(e){showError(e)}}
async function refreshProjectFiles(){if(!wid)return;const pid=el('safeProject').value;el('safeFile').replaceChildren();if(!pid)return;try{const files=await req('/workspaces/'+encodeURIComponent(wid)+'/projects/'+encodeURIComponent(pid)+'/files');selectOptions(el('safeFile'),files,x=>x.filename+' Ã‚Â· '+x.sha256.slice(0,10));}catch(e){showError(e)}}
async function refreshActions(){if(!wid)return;try{const actions=await api('');const target=el('safeActions');target.replaceChildren();for(const action of actions){const line=document.createElement('div');line.style.padding='9px 0';const b=document.createElement('button');b.textContent=action.tool+' Ã‚Â· '+action.status+' Ã‚Â· '+action.id.slice(0,8);b.type='button';b.onclick=()=>openAction(action.id);line.append(b);target.append(line)}if(!actions.length)set('safeStatus','No tool actions in this workspace yet.')}catch(e){showError(e)}}
async function openAction(id){try{const item=await api('/'+id);el('safeSelected').value=id;const root=el('safeDetail');root.replaceChildren();const add=text=>{const p=document.createElement('p');p.textContent=text;root.append(p)};add('Tool: '+item.action.tool+' Ã‚Â· '+item.action.status);add('Source SHA-256: '+item.action.source_sha256);add('Requested by: '+item.action.requested_by);if(item.review)add('Review: '+item.review.decision+' by '+item.review.reviewer_id+' Ã‚Â· '+item.review.rationale);for(const linked of (item.linked_plan_steps||[]))add('Linked evidence: plan '+linked.plan_id+' Ã‚Â· step '+linked.step_id+' Ã‚Â· result SHA-256 '+linked.result_sha256);for(const attempt of item.attempts){add('Actual attempt: '+attempt.status+' Ã‚Â· '+attempt.provider+' Ã‚Â· '+(attempt.result_sha256||'no result hash'));const pre=document.createElement('pre');pre.textContent=attempt.result?JSON.stringify(attempt.result,null,2):(attempt.error||'No result');root.append(pre)}const v=await api('/'+id+'/verify');add('Evidence verification: '+v.source_state);for(const c of v.checks)add('Attempt fingerprint intact: '+String(c.result_fingerprint_intact));}catch(e){showError(e)}}
window.addEventListener('load',()=>{
 el('safeProject').addEventListener('change',refreshProjectFiles);
 async function populatePlans(){if(!wid)return;try{const plans=await req('/workspaces/'+encodeURIComponent(wid)+'/orchestration/plans');selectOptions(el('safePlan'),plans,x=>x.goal.slice(0,90));await populateSteps()}catch(e){showError(e)}}
 async function populateSteps(){if(!wid||!el('safePlan').value){el('safeStep').replaceChildren();return}try{const info=await req('/workspaces/'+encodeURIComponent(wid)+'/orchestration/plans/'+encodeURIComponent(el('safePlan').value));selectOptions(el('safeStep'),info.steps,x=>(x.position+1)+'. '+x.title)}catch(e){showError(e)}}
 el('safePlan').onchange=populateSteps;
 el('safeLink').onclick=async()=>{try{const aid=el('safeSelected').value,plan=el('safePlan').value,step=el('safeStep').value;if(!aid||!plan||!step)throw Error('Select a completed action, plan and step');const r=await api('/'+aid+'/link-plan',{plan_id:plan,step_id:step});set('safeStatus','Verified tool result linked; step not automatically completed');await openAction(aid)}catch(e){showError(e)}};
 el('safeRefresh').onclick=async()=>{await refreshFiles();await refreshActions();await populatePlans()};
 el('safePropose').onsubmit=async e=>{e.preventDefault();try{if(!wid)throw Error('Select a workspace first');const tool=el('safeTool').value;const first=el('safeColumn').value.trim(),second=el('safeColumnB').value.trim();const parameterKeys={'csv.numeric_stats':['column'],'csv.correlation':['x','y'],'csv.linear_model':['x','y'],'csv.finance_summary':['revenue','cost'],'csv.group_summary':['group','value'],'json.numeric_summary':['key']};const keys=parameterKeys[tool]||[];const parameters={};if(keys[0])parameters[keys[0]]=first;if(keys[1])parameters[keys[1]]=second;const a=await api('',{project_id:el('safeProject').value,file_id:el('safeFile').value,tool,parameters,reason:el('safeReason').value});set('safeStatus','Proposed '+a.id+'; no tool executed');await refreshActions();await openAction(a.id)}catch(err){showError(err)}};
 el('safeReview').onclick=async()=>{try{const id=el('safeSelected').value;if(!id)throw Error('Choose an action');const decision=el('safeDecision').value;const rationale=el('safeReviewReason').value;await api('/'+id+'/review',{decision,rationale});set('safeStatus','Decision recorded');await refreshActions();await openAction(id)}catch(e){showError(e)}};
 el('safeExecute').onclick=async()=>{try{const id=el('safeSelected').value;if(!id)throw Error('Choose an action');if(!confirm('Run the approved read-only file tool? No arbitrary code will run.'))return;const result=await api('/'+id+'/run',{acknowledgement:true});set('safeStatus','Actual tool status: '+result.status);await refreshActions();await openAction(id)}catch(e){showError(e)}};
});
})();

</script>
<script>
(function(){
const id=x=>document.getElementById(x), msg=x=>id('revStatus').textContent=x;
let selected=null;
const api=(tail,body)=>req('/workspaces/'+encodeURIComponent(wid)+'/repo-revisions'+tail,body);
function line(el,s){const p=document.createElement('p');p.textContent=s;el.append(p)}
async function openRevision(rid){
 try{selected=rid;const r=await api('/'+encodeURIComponent(rid));const area=id('revDetail');area.replaceChildren();
 line(area,'Revision '+r.id.slice(0,10)+' Ã‚Â· '+r.status+' Ã‚Â· '+r.target_path);
 line(area,'Source SHA-256: '+r.source_sha256);
 line(area,'Requester: '+r.requested_by+(r.review_by?' Ã‚Â· Reviewer: '+r.review_by:''));
 if(r.review_rationale)line(area,'Review: '+r.review_decision+' Ã‚Â· '+r.review_rationale);
 const pre=document.createElement('pre');pre.textContent=r.preview.diff;area.append(pre);
 line(area,'Python AST checked: '+r.preview.python_syntax_checked+' Ã‚Â· Runtime tests executed: false');
 if(r.staged_file_id){const result=await api('/'+encodeURIComponent(rid)+'/verify');
 line(area,'Staged ZIP integrity verified: '+result.verified+' Ã‚Â· SHA-256: '+r.staged_sha256);
 const a=document.createElement('a');a.href='/api/team/workspaces/'+encodeURIComponent(wid)+'/projects/'+encodeURIComponent(r.project_id)+'/files/'+encodeURIComponent(r.staged_file_id)+'/download';a.textContent='Download staged ZIP';area.append(a)}
 }catch(e){msg(e.message||String(e))}
}
async function refresh(){if(!wid)return;try{const items=await api('');const root=id('revHistory');root.replaceChildren();
 for(const item of items){const b=document.createElement('button');b.type='button';b.style.margin='5px';
 b.textContent=item.target_path+' Ã‚Â· '+item.status;b.onclick=()=>openRevision(item.id);root.append(b)}
 if(!items.length)line(root,'No revisions yet.')}catch(e){msg(e.message||String(e))}}
window.addEventListener('load',()=>{
 id('revRefresh').onclick=refresh;
 id('revPropose').onsubmit=async e=>{e.preventDefault();try{
 if(!wid||!id('safeProject').value||!id('safeFile').value)throw Error('Choose a team project and ZIP file in Verified File Tools first');
 const r=await api('',{project_id:id('safeProject').value,file_id:id('safeFile').value,
 target_path:id('revTarget').value,existing_text:id('revOld').value,replacement_text:id('revNew').value,reason:id('revReason').value});
 msg('Revision proposed; source unchanged.');await refresh();await openRevision(r.id)
 }catch(err){msg(err.message||String(err))}};
 id('revReview').onclick=async()=>{try{if(!selected)throw Error('Choose a revision first');
 await api('/'+encodeURIComponent(selected)+'/review',{decision:id('revDecision').value,rationale:id('revRationale').value});
 msg('Reviewer decision saved.');await refresh();await openRevision(selected)
 }catch(err){msg(err.message||String(err))}};
 id('revStage').onclick=async()=>{try{if(!selected)throw Error('Choose a revision first');
 if(!confirm('Stage approved ZIP as a new immutable artifact? Original will be preserved. No tests will be executed.'))return;
 const result=await api('/'+encodeURIComponent(selected)+'/stage',{acknowledgement:true});
 msg('Created artifact '+result.artifact_file_id+'; runtime tests NOT executed.');await refresh();await openRevision(selected)
 }catch(err){msg(err.message||String(err))}};
});
})();
</script>
<script>
(()=>{
const byId=id=>document.getElementById(id), api=async(path,body)=>{const response=await fetch('/api/team'+path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});const result=await response.json();if(!response.ok)throw new Error(result.detail||'Request failed');return result;};
let current='';
const panel=byId('exeStatus');
async function update(){if(!wid)return;try{const root='/workspaces/'+encodeURIComponent(wid),[revs,requests]=await Promise.all([api(root+'/repo-revisions'),api(root+'/execution-requests')]);let selector=byId('exeRevision');selector.replaceChildren();for(const r of revs.filter(r=>r.status==='staged')){let option=document.createElement('option');option.value=r.id;option.textContent=(r.target_path||r.id)+' Ã‚Â· '+r.id.slice(0,9);selector.appendChild(option);}const history=byId('exeHistory');history.replaceChildren();for(const item of requests){const box=document.createElement('div');box.style.margin='12px 0';const summary=document.createElement('p');summary.textContent=item.selector+' Ã‚Â· '+item.status+' Ã‚Â· '+item.id.slice(0,10);box.append(summary);const inspect=document.createElement('button');inspect.type='button';inspect.textContent='Inspect';inspect.onclick=()=>{panel.textContent=JSON.stringify(item.manifest||{status:item.status,reason:item.reason},null,2)};box.append(inspect);if(item.status==='proposed'&&['owner','admin'].includes(role)){for(const decision of ['approve','reject']){const button=document.createElement('button');button.type='button';button.textContent=decision;button.style.marginLeft='6px';button.onclick=async()=>{const rationale=prompt('Independent review rationale (12+ characters):');if(!rationale)return;try{await api(root+'/execution-requests/'+item.id+'/review',{decision,rationale});await update()}catch(e){panel.textContent=e.message}};box.append(button)}}if(item.status==='approved'&&canEdit()){const button=document.createElement('button');button.textContent='Prepare isolated-worker manifest';button.type='button';button.onclick=async()=>{try{const r=await api(root+'/execution-requests/'+item.id+'/prepare',{acknowledgement:true});panel.textContent='Manifest saved. No worker connected. '+r.manifest_sha256;await update()}catch(e){panel.textContent=e.message}};box.append(button)}history.append(box)}}catch(e){panel.textContent=e.message}}
byId('exeRefresh').onclick=update;byId('exePropose').onsubmit=async ev=>{ev.preventDefault();if(!wid)return;try{await api('/workspaces/'+encodeURIComponent(wid)+'/execution-requests',{revision_id:byId('exeRevision').value,selector:byId('exeSelector').value,reason:byId('exeReason').value});byId('exeReason').value='';await update()}catch(e){panel.textContent=e.message}};
window.addEventListener('load',()=>{const button=byId('exeRefresh');if(button)button.disabled=false});
})();
</script><script>
(()=>{
const output=document.getElementById('workerHistory');
const status=document.getElementById('workerStatus');
const refresh=async()=>{
 if(!wid)return;
 output.replaceChildren(); status.textContent='Checking worker handoff recordsÃ¢â‚¬Â¦';
 try{
  const root='/workspaces/'+encodeURIComponent(wid);
  const [caps,records]=await Promise.all([req(root+'/worker-handoffs/capabilities'),req(root+'/worker-handoffs')]);
  status.textContent=caps.handoff_enabled?'External report key configured; isolation not attested.':'No external worker configured. No repository code can be executed.';
  if(!records.length){const p=document.createElement('p');p.textContent='No worker handoffs yet.';output.append(p);return;}
  for(const r of records){
   const box=document.createElement('div');box.style.margin='12px 0';
   const label=document.createElement('p');label.textContent=r.id.slice(0,10)+' Ã‚Â· '+r.status+' Ã‚Â· '+(r.reported_at||r.created_at);box.append(label);
   const inspect=document.createElement('button');inspect.type='button';inspect.textContent='Inspect report';
   inspect.onclick=async()=>{try{const d=await req(root+'/worker-handoffs/'+encodeURIComponent(r.id));const pre=document.createElement('pre');pre.textContent=JSON.stringify({status:d.status,report:d.external_report||null,report_authenticated:d.report_authenticated,worker_isolation_attested:false},null,2);box.append(pre);inspect.disabled=true}catch(e){status.textContent=e.message}};
   box.append(inspect);output.append(box);
  }
 }catch(e){status.textContent=e.message||String(e)}
};
const button=document.getElementById('workerRefresh');if(button)button.onclick=refresh;
})();
</script><script>
(function(){
const el=x=>document.getElementById(x); const status=x=>el('unifiedStatus').textContent=x;
async function loadUnified(){if(!wid)return;try{
 const [inv,briefs]=await Promise.all([req('/workspaces/'+wid+'/investigations'),req('/workspaces/'+wid+'/unified/briefs')]);
 const sel=el('unifiedInvestigation');sel.replaceChildren();
 for(const v of inv){const o=document.createElement('option');o.value=v.id;o.textContent=v.question.slice(0,100);sel.append(o)}
 const history=el('unifiedHistory');history.replaceChildren();
 for(const b of briefs){const wrap=document.createElement('p');const label=document.createElement('span');label.textContent=b.title+' Ã‚Â· '+b.created_at+' ';
 const link=document.createElement('a');link.href='/api/team/workspaces/'+encodeURIComponent(wid)+'/unified/briefs/'+encodeURIComponent(b.id)+'/export';link.textContent='Export Markdown';
 const check=document.createElement('button');check.type='button';check.textContent='Check freshness';check.onclick=async()=>{try{const f=await req('/workspaces/'+wid+'/unified/briefs/'+b.id+'/freshness');status(f.matches_current_records?'Brief matches current records.':'Historical brief: underlying records changed.')}catch(e){status(e.message)}};
 wrap.append(label,link,check);history.append(wrap)}
 if(!briefs.length)history.textContent='No saved briefs yet.'
}catch(e){status(e.message)}}
el('unifiedLoad').onclick=loadUnified;
el('unifiedPreview').onclick=async()=>{if(!wid||!el('unifiedInvestigation').value)return;try{
 const p=await req('/workspaces/'+wid+'/unified/investigations/'+el('unifiedInvestigation').value+'/preview');
 el('unifiedPreviewText').textContent=JSON.stringify({candidate_domains:p.domains,integrity:p.integrity,gaps:p.gaps,sources:p.sources.map(s=>({filename:s.filename,state:s.state,has_extracted_text:s.has_extracted_text})),tool_actions:p.tool_actions.map(a=>({tool:a.tool,integrity:a.integrity})),saved_model_reviews:p.ness_reviews.length,plans:p.plans.length,approvals:p.approvals.length},null,2);
 status('Read-only preview. No Meta model call or repository execution occurred.');
}catch(e){status(e.message)}};
el('unifiedNessReview').onclick=async()=>{if(!wid||!el('unifiedInvestigation').value)return;try{status('Calling the configured AI provider using saved investigation evidence.');const r=await req('/workspaces/'+wid+'/investigations/'+el('unifiedInvestigation').value+'/ness-review',{});status('Model review saved. Check provider and response in the investigation. This is AI analysis, not independently verified evidence.');await el('unifiedPreview').onclick();}catch(e){status('Ness review failed: '+e.message+' (check actual Meta connection and evidence extraction).')}};
el('unifiedSave').onsubmit=async e=>{e.preventDefault();if(!wid)return;try{
 await req('/workspaces/'+wid+'/unified/briefs',{investigation_id:el('unifiedInvestigation').value,title:el('unifiedTitle').value,interpretation:el('unifiedInterpretation').value,limitations:el('unifiedLimitations').value});status('Saved a new historical brief.');await loadUnified();
}catch(err){status(err.message)}};
})();
</script>
<script>
(()=>{
const g=id=>document.getElementById(id), root=()=>'/workspaces/'+wid+'/brief-collaboration';
const message=s=>{g('briefTeamStatus').textContent=s};
let snapshot=null;
const selected=()=>g('briefTeamSelect').value;
async function load(){if(!wid)return;try{const all=await req('/workspaces/'+wid+'/unified/briefs');const menu=g('briefTeamSelect');const previous=menu.value;menu.replaceChildren();for(const b of all){const o=document.createElement('option');o.value=b.id;o.textContent=b.title+' Ã‚Â· '+b.id.slice(0,8);menu.append(o)}if(all.some(b=>b.id===previous))menu.value=previous;message(all.length?all.length+' saved briefs available':'No saved briefs. Create one in Unified Investigation Brief.');}catch(e){message(e.message)}}
async function open(){if(!selected())return;try{const b=await req(root()+'/'+selected());snapshot=b;const out=g('briefTeamView');out.replaceChildren();const heading=document.createElement('p');heading.textContent='Review: '+b.review_state+' Ã‚Â· Source freshness: '+(b.matches_current_evidence?'current':'STALE')+' Ã‚Â· '+b.comments.length+' comments Ã‚Â· '+b.followups.length+' follow-ups';out.append(heading);for(const c of b.comments){const p=document.createElement('p');p.textContent='Comment ['+c.actor_id.slice(0,8)+']: '+c.body+(c.source_file_id?' Ã‚Â· evidence '+c.source_file_id.slice(0,8):'');out.append(p)}for(const t of b.followups){const p=document.createElement('p');p.textContent='Follow-up '+t.title+' ['+t.status+'] Ã‚Â· '+t.priority+(t.assigned_to?' Ã‚Â· assigned '+t.assigned_to.slice(0,8):'');out.append(p)}for(const r of b.reviews){const p=document.createElement('p');p.textContent='Human decision: '+r.decision+' Ã¢â‚¬â€ '+r.rationale;out.append(p)}const detail=await req('/workspaces/'+wid+'/unified/briefs/'+selected());const sources=g('briefTeamSource');sources.replaceChildren();const blank=document.createElement('option');blank.value='';blank.textContent='General discussion';sources.append(blank);for(const source of detail.snapshot.sources){const o=document.createElement('option');o.value=source.id;o.textContent=source.filename;sources.append(o)}message('Loaded human review of saved historical brief.');}catch(e){message(e.message)}}
g('briefTeamLoad').onclick=load;g('briefTeamOpen').onclick=open;
g('briefTeamComment').onsubmit=async e=>{e.preventDefault();if(!selected())return;try{await req(root()+'/'+selected()+'/comments',{body:g('briefTeamBody').value,source_file_id:g('briefTeamSource').value||null});g('briefTeamBody').value='';await open()}catch(err){message(err.message)}};
g('briefTeamTask').onsubmit=async e=>{e.preventDefault();if(!selected())return;try{await req(root()+'/'+selected()+'/followups',{title:g('briefTeamTaskTitle').value,description:g('briefTeamTaskText').value,priority:g('briefTeamPriority').value});g('briefTeamTaskTitle').value='';g('briefTeamTaskText').value='';await open()}catch(err){message(err.message)}};
g('briefTeamReview').onsubmit=async e=>{e.preventDefault();if(!selected())return;try{await req(root()+'/'+selected()+'/reviews',{decision:g('briefTeamDecision').value,rationale:g('briefTeamRationale').value});g('briefTeamRationale').value='';await open()}catch(err){message(err.message)}};
})();

// Meta Model Lab: all output is text-only, never inserted as HTML.
(function(){
 const $=id=>document.getElementById(id), output=$('metaOutput');
 async function getJson(path,options){const res=await fetch(path,{credentials:'same-origin',...options});let val=await res.json();if(!res.ok)throw Error(val.detail||('HTTP '+res.status));return val;}
 function show(data){output.textContent=JSON.stringify(data,null,2);}
 function opt(select,values){select.replaceChildren(...values.map(v=>{const o=document.createElement('option');o.value=v.id;o.textContent=v.label;return o;}));}
 function activeWorkspace(){return wid;}
 async function investigations(){if(!activeWorkspace())return;const rows=await getJson('/api/team/workspaces/'+encodeURIComponent(activeWorkspace())+'/investigations');opt($('metaInvestigation'),rows.map(r=>({id:r.id,label:r.question.slice(0,95)})));}
 async function comparisons(){if(!activeWorkspace())return;const rows=await getJson('/api/team/workspaces/'+encodeURIComponent(activeWorkspace())+'/meta-model-lab/comparisons');opt($('metaComparison'),rows.map(r=>({id:r.id,label:r.question.slice(0,75)})));}
 $('metaCatalog').addEventListener('click',async()=>{try{$('metaCatalogOut').textContent=JSON.stringify(await getJson('/api/team/meta-model-lab/catalog'),null,2);await investigations();await comparisons();}catch(e){show({error:e.message});}});
 $('metaProbeRun').addEventListener('click',async()=>{try{show(await getJson('/api/team/meta-model-lab/probe',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:$('metaProbe').value})}));}catch(e){show({error:e.message});}});
 $('metaCompareRun').addEventListener('click',async()=>{try{const models=[$('metaModelA').value,$('metaModelB').value].filter(Boolean);show(await getJson('/api/team/workspaces/'+encodeURIComponent(activeWorkspace())+'/meta-model-lab/compare',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({investigation_id:$('metaInvestigation').value,question:$('metaQuestion').value,models})}));await comparisons();}catch(e){show({error:e.message});}});
 $('metaCompareRefresh').addEventListener('click',async()=>{try{await investigations();await comparisons();show({status:'Comparisons loaded'});}catch(e){show({error:e.message});}});
 $('metaComparisonOpen').addEventListener('click',async()=>{try{show(await getJson('/api/team/workspaces/'+encodeURIComponent(activeWorkspace())+'/meta-model-lab/comparisons/'+encodeURIComponent($('metaComparison').value)));}catch(e){show({error:e.message});}});
})();
</script><script>
(()=>{
 const target=document.getElementById('advancedOutput');
 const node=id=>document.getElementById(id);
 async function call(path,options){const response=await fetch('/api/team'+path,{credentials:'same-origin',...options});const data=await response.json();if(!response.ok)throw Error(typeof data.detail==='string'?data.detail:'HTTP '+response.status);return data;}
 function workspace(){return typeof wid!=='undefined'?wid:null;}
 function options(select,rows,label){select.replaceChildren();for(const item of rows){const option=document.createElement('option');option.value=item.id;option.textContent=label(item);select.append(option);}}
 async function run(work){try{if(!workspace())throw Error('Choose a workspace first');target.textContent=JSON.stringify(await work(),null,2);}catch(error){target.textContent='Error: '+error.message;}}
 async function load(){const list=await call('/workspaces/'+encodeURIComponent(workspace())+'/investigations');options(node('advancedInvestigation'),list,item=>item.question.slice(0,95));return {investigations:list.length};}
 node('advancedLoad').onclick=()=>run(load);
 node('advancedPreview').onclick=()=>run(()=>call('/workspaces/'+encodeURIComponent(workspace())+'/advanced/preview/'+encodeURIComponent(node('advancedInvestigation').value)));
 node('advancedSave').onsubmit=event=>{event.preventDefault();run(()=>call('/workspaces/'+encodeURIComponent(workspace())+'/advanced/syntheses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({investigation_id:node('advancedInvestigation').value,title:node('advancedTitle').value,assessment:node('advancedAssessment').value})}));};
 node('advancedList').onclick=()=>run(async()=>{const list=await call('/workspaces/'+encodeURIComponent(workspace())+'/advanced/syntheses');options(node('advancedSaved'),list,item=>item.title);return {saved:list.length};});
 node('advancedOpen').onclick=()=>run(()=>call('/workspaces/'+encodeURIComponent(workspace())+'/advanced/syntheses/'+encodeURIComponent(node('advancedSaved').value)));
})();
</script><script src="/static/verynth-focus.js" defer></script><script>document.addEventListener('click',async e=>{if(e.target?.id!=='meetingCreate')return;const out=document.getElementById('meetingLink');try{if(!wid)throw Error('Choose a workspace first');const r=await fetch('/api/team/workspaces/'+encodeURIComponent(wid)+'/meetings',{method:'POST',credentials:'same-origin'});const d=await r.json();if(!r.ok)throw Error(d.detail||'Could not create meeting');out.replaceChildren();const a=document.createElement('a');a.href=d.url;a.textContent='Open meeting room';a.target='_blank';out.append(a,document.createTextNode(' Ã‚Â· Copy this link to invited workspace members: '+location.origin+d.url))}catch(err){out.textContent=err.message}});</script></body></html>'''
