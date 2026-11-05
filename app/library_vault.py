"""VERYNTH private Library: scoped file inventory and saved report export.

No phantom files, no movement between trust boundaries, no duplicate blobs.
Search over extracted text only when it already exists; never claim OCR or indexing.
"""
import hashlib
import json
import re
from pathlib import Path
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, Field

class LibraryChange(BaseModel):
    name:str=Field(min_length=1,max_length=180)
class LibraryFolder(BaseModel):
    collection:str=Field(default='',max_length=80)

def register_library(router, connection, now, actor, member, event, storage):
    with connection() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS library_metadata(
          file_id TEXT PRIMARY KEY, display_name TEXT, collection TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS ix_library_files_project ON files(project_id,created_at);
        ''')

    def allowed_projects(db, who):
        rows=db.execute('''SELECT l.project_id,l.workspace_id,p.name AS project_name,w.kind,
                 m.role FROM collab_project_links l JOIN collab_workspaces w ON w.id=l.workspace_id
                 JOIN collab_memberships m ON m.workspace_id=l.workspace_id AND m.user_id=?
                 JOIN projects p ON p.id=l.project_id''',(who['id'],)).fetchall()
        return {r['project_id']:dict(r) for r in rows}

    def accessible_file(db,who,fid,minimum='viewer'):
        f=db.execute('SELECT * FROM files WHERE id=?',(fid,)).fetchone()
        if not f:raise HTTPException(404,'File not found')
        linked=allowed_projects(db,who).get(f['project_id'])
        if not linked:raise HTTPException(404,'File not found')
        if member is not None:
            member(db,linked['workspace_id'],who,minimum)
        return f,linked

    def bounded_file(f):
        p=Path(f['storage_path']).resolve();root=Path(storage).resolve()
        if p.parent!=root or p.name!=f['id']:raise HTTPException(409,'Stored file path failed integrity check')
        if not p.is_file():raise HTTPException(404,'File missing from evidence storage')
        h=hashlib.sha256()
        with p.open('rb') as handle:
            for chunk in iter(lambda:handle.read(1024*1024),b''):h.update(chunk)
        if h.hexdigest()!=f['sha256']:raise HTTPException(409,'File SHA-256 integrity check failed')
        return p

    def scope(db,who):
        return allowed_projects(db,who)

    @router.get('/library')
    def library(request:Request,q:str='',kind:str='all',collection:str='',limit:int=150):
        who=actor(request)
        if kind not in ('all','upload','generated','shared'):raise HTTPException(422,'Unknown library filter')
        if len(q)>150 or len(collection)>80 or limit<1 or limit>250:raise HTTPException(422,'Invalid search')
        with connection() as db:
            projects=scope(db,who)
            if not projects:return {'items':[],'collections':[],'search_scope':'Existing filenames, project names and already-extracted text only'}
            placeholders=','.join('?' for _ in projects)
            search=q.casefold().strip();items=[]
            rows=db.execute(f'''SELECT f.id,f.project_id,f.filename,f.mime,f.size,f.sha256,f.extract_status,
                 f.created_at,f.extracted_text,meta.display_name,meta.collection
                 FROM files f LEFT JOIN library_metadata meta ON meta.file_id=f.id
                 WHERE f.project_id IN ({placeholders}) ORDER BY f.created_at DESC LIMIT 1000''',tuple(projects)).fetchall()
            for r in rows:
                project=projects[r['project_id']];shared=project['kind']=='team'
                name=r['display_name'] or r['filename']
                if kind=='generated' or (kind=='shared' and not shared):continue
                if collection and (r['collection'] or '')!=collection:continue
                if search and not any(search in str(s or '').casefold() for s in (name,project['project_name'],r['mime'],r['extracted_text'][:250000])):continue
                items.append({'id':r['id'],'kind':'upload','filename':name,'original_filename':r['filename'],
                  'project_id':r['project_id'],'project_name':project['project_name'],
                  'workspace_id':project['workspace_id'],'workspace_kind':project['kind'],'role':project['role'],
                  'shared':shared,'mime':r['mime'],'size':r['size'],'created_at':r['created_at'],
                  'extract_status':r['extract_status'],'sha256':r['sha256'],'collection':r['collection'] or '',
                  'has_preview':bool(r['extracted_text'].strip()),'source':'Saved uploaded evidence'})
            # Derived reports are read from the real saved-report table, not made-up files.
            if kind in ('all','generated','shared') and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='team_unified_briefs'").fetchone():
                for b in db.execute(f'''SELECT id,workspace_id,project_id,title,created_at FROM team_unified_briefs
                    WHERE project_id IN ({placeholders}) ORDER BY created_at DESC LIMIT 250''',tuple(projects)):
                    project=projects.get(b['project_id'])
                    if not project or b['workspace_id']!=project['workspace_id']:continue
                    shared=project['kind']=='team'
                    if kind=='shared' and not shared:continue
                    if collection:continue
                    filename=b['title']+'.md'
                    if search and not any(search in str(v).casefold() for v in (filename,project['project_name'],'investigation report')):continue
                    items.append({'id':b['id'],'kind':'generated','output_type':'brief','filename':filename,'project_id':b['project_id'],
                      'project_name':project['project_name'],'workspace_id':project['workspace_id'],'workspace_kind':project['kind'],
                      'role':project['role'],'shared':shared,'mime':'text/markdown','size':None,'created_at':b['created_at'],
                      'collection':'','has_preview':True,'source':'Saved Unified Investigation Brief'})
            # Advanced syntheses and engineering dossiers are real persisted output records.
            # Expose their saved snapshots as downloadable JSON, never fabricate a file blob.
            if kind in ('all','generated','shared'):
                for table,out_type in [('team_advanced_syntheses','synthesis'),('team_engineering_dossiers','dossier')]:
                    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone():continue
                    if out_type=='dossier':
                        rs=db.execute(f"SELECT id,workspace_id,project_id,title,created_at FROM {table} ORDER BY created_at DESC LIMIT 300").fetchall()
                    else:
                        rs=db.execute(f"SELECT s.id,s.workspace_id,i.project_id,s.title,s.created_at FROM {table} s JOIN team_investigations i ON i.id=s.investigation_id AND i.workspace_id=s.workspace_id ORDER BY s.created_at DESC LIMIT 300").fetchall()
                    for b in rs:
                        proj=projects.get(b['project_id'])
                        if not proj or proj['workspace_id']!=b['workspace_id']:continue
                        shared=proj['kind']=='team'
                        if kind=='shared' and not shared:continue
                        if collection:continue
                        name=b['title']+'.json'
                        if search and not any(search in str(v).casefold() for v in (name,proj['project_name'],out_type)):continue
                        items.append({'id':b['id'],'kind':'generated','output_type':out_type,'filename':name,
                           'project_id':b['project_id'],'project_name':proj['project_name'],
                           'workspace_id':proj['workspace_id'],'workspace_kind':proj['kind'],'role':proj['role'],
                           'shared':shared,'mime':'application/json','size':None,'created_at':b['created_at'],
                           'collection':'','has_preview':True,'source':'Saved '+('Advanced Intelligence Synthesis' if out_type=='synthesis' else 'Engineering Evidence Dossier')})
            items.sort(key=lambda x:x['created_at'],reverse=True)
            all_collections=sorted({(r['collection'] or '') for r in rows if r['collection']})
            return {'items':items[:limit],'collections':all_collections,'total_matching':len(items),
              'search_scope':'Filename, project name, MIME type and existing extracted text. Generated report text is not indexed.'}

    @router.get('/library/files/{fid}/preview')
    def preview(fid:str,request:Request):
        who=actor(request)
        with connection() as db:
            f,_=accessible_file(db,who,fid)
            bounded_file(f)
            text=f['extracted_text'] or ''
            # Text preview must never transform an inert file into active HTML.
            return {'filename':f['filename'],'extract_status':f['extract_status'],
              'preview':text[:24000],'truncated':len(text)>24000,'has_text':bool(text.strip()),
              'notice':'Preview is already-extracted text, not a new analysis. Download for original content.'}

    @router.get('/library/files/{fid}/download')
    def download(fid:str,request:Request):
        who=actor(request)
        with connection() as db:
            f,_=accessible_file(db,who,fid)
            p=bounded_file(f)
            meta=db.execute('SELECT display_name FROM library_metadata WHERE file_id=?',(fid,)).fetchone()
            name=meta['display_name'] if meta and meta['display_name'] else f['filename']
            return FileResponse(p,filename=name,media_type='application/octet-stream',
              headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'})

    @router.patch('/library/files/{fid}/rename')
    def rename(fid:str,body:LibraryChange,request:Request):
        who=actor(request);name=body.name.strip()
        if name in ('.','..') or '/' in name or '\\' in name or not name or any(ord(c)<32 for c in name):
            raise HTTPException(422,'Invalid filename')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE')
            f,linked=accessible_file(db,who,fid,'editor')
            # Change display name only: never alter original evidence or SHA/provenance.
            db.execute('''INSERT INTO library_metadata(file_id,display_name,collection,updated_at) VALUES(?,?,?,?)
                 ON CONFLICT(file_id) DO UPDATE SET display_name=excluded.display_name,updated_at=excluded.updated_at''',
                 (fid,name,'',now()))
            event(db,linked['workspace_id'],who,'library_file_renamed',fid,{'display_name':name})
        return {'renamed':True,'filename':name,'original_evidence_unchanged':True}

    @router.patch('/library/files/{fid}/collection')
    def move_to_collection(fid:str,body:LibraryFolder,request:Request):
        who=actor(request);collection=body.collection.strip()
        if any(x in collection for x in ('/','\\','\x00')):raise HTTPException(422,'Invalid collection name')
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');f,linked=accessible_file(db,who,fid,'editor')
            db.execute('''INSERT INTO library_metadata(file_id,collection,updated_at) VALUES(?,?,?)
                    ON CONFLICT(file_id) DO UPDATE SET collection=excluded.collection,updated_at=excluded.updated_at''',
                    (fid,collection,now()))
            event(db,linked['workspace_id'],who,'library_collection_changed',fid,{'collection':collection})
        return {'moved':True,'collection':collection,'project_link_unchanged':True}

    @router.delete('/library/files/{fid}')
    def remove(fid:str,request:Request):
        who=actor(request)
        # Permanent deletion only for unreferenced evidence. Do not break saved investigations.
        with connection() as db:
            db.execute('BEGIN IMMEDIATE');f,linked=accessible_file(db,who,fid,'editor')
            p=bounded_file(f)
            tables=[x['name'] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for table in tables:
                if table in ('files','library_metadata'):continue
                if not re.fullmatch(r'[A-Za-z0-9_]+',table):continue
                cols=[x['name'] for x in db.execute(f'PRAGMA table_info("{table}")')]
                for col in cols:
                    if col in ('file_id','source_file_id','staged_file_id','original_file_id','artifact_file_id','evidence_file_id'):
                        if db.execute(f'SELECT 1 FROM "{table}" WHERE "{col}"=? LIMIT 1',(fid,)).fetchone():
                            raise HTTPException(409,'File is referenced by an investigation or saved result; deletion blocked to preserve evidence.')
            # Fail closed for file IDs embedded in older saved JSON evidence payloads.
            # A conservative text match may block deletion rather than orphan a record.
            for table in tables:
                if table in ('files','library_metadata') or not re.fullmatch(r'[A-Za-z0-9_]+',table):continue
                for col in [x['name'] for x in db.execute(f'PRAGMA table_info("{table}")')]:
                    if col.endswith('_json') or col in ('snapshot_json','content_json','result_json'):
                        if not re.fullmatch(r'[A-Za-z0-9_]+',col):continue
                        if db.execute(f'SELECT 1 FROM "{table}" WHERE instr("{col}",?)>0 LIMIT 1',(fid,)).fetchone():
                            raise HTTPException(409,'Saved JSON references this evidence; deletion blocked.')
            db.execute('DELETE FROM library_metadata WHERE file_id=?',(fid,))
            db.execute('DELETE FROM files WHERE id=?',(fid,))
            event(db,linked['workspace_id'],who,'library_file_deleted',fid,{'filename':f['filename']})
        # Database deletion is committed before blob removal; no arbitrary filesystem paths.
        p.unlink(missing_ok=True)
        return {'deleted':True}

    @router.get('/library/reports/{bid}/preview')
    def report_preview(bid:str,request:Request):
        who=actor(request)
        with connection() as db:
            b=db.execute('SELECT * FROM team_unified_briefs WHERE id=?',(bid,)).fetchone()
            if not b or b['project_id'] not in scope(db,who) or b['workspace_id']!=scope(db,who)[b['project_id']]['workspace_id']:
                raise HTTPException(404,'Report not found')
            return {'filename':b['title']+'.md','preview':b['report_markdown'][:24000],
                'truncated':len(b['report_markdown'])>24000,'has_text':True,
                'notice':'Saved report; source verification status must be checked in its investigation.'}

    @router.get('/library/reports/{bid}/download')
    def report_download(bid:str,request:Request):
        who=actor(request)
        with connection() as db:
            b=db.execute('SELECT * FROM team_unified_briefs WHERE id=?',(bid,)).fetchone()
            if not b or b['project_id'] not in scope(db,who) or b['workspace_id']!=scope(db,who)[b['project_id']]['workspace_id']:
                raise HTTPException(404,'Report not found')
            # This is an existing saved report. It is not independently revalidated here.
            name=re.sub(r'[^A-Za-z0-9._-]','_',b['title'])[:90] or 'investigation'
            return PlainTextResponse(b['report_markdown'],headers={'Content-Disposition':f'attachment; filename="{name}.md"',
              'Cache-Control':'no-store'})

    def output_document(db,who,output_type,oid):
        if output_type not in ('synthesis','dossier'):raise HTTPException(404,'Output not found')
        table={'synthesis':'team_advanced_syntheses','dossier':'team_engineering_dossiers'}[output_type]
        row=db.execute(f'SELECT * FROM {table} WHERE id=?',(oid,)).fetchone()
        if not row:raise HTTPException(404,'Output not found')
        pid=row['project_id'] if output_type=='dossier' else None
        if pid is None:
            inv=db.execute('SELECT project_id FROM team_investigations WHERE workspace_id=? AND id=?',
                           (row['workspace_id'],row['investigation_id'])).fetchone()
            pid=inv['project_id'] if inv else None
        projects=scope(db,who)
        if not pid or pid not in projects or row['workspace_id']!=projects[pid]['workspace_id']:
            raise HTTPException(404,'Output not found')
        raw=row['snapshot_json'];saved=json.loads(raw)
        fingerprint=hashlib.sha256(json.dumps({k:v for k,v in saved.items() if k!='fingerprint'},
                           sort_keys=True,ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
        if saved.get('fingerprint')!=row['fingerprint'] or fingerprint!=row['fingerprint']:
            raise HTTPException(409,'Saved output integrity check failed')
        return {'title':row['title'],'kind':output_type,'snapshot':saved,
           'human_assessment':row['assessment'] if output_type=='synthesis' else row['interpretation'],
           'fingerprint':row['fingerprint'], 'limitations':'Saved model/simulation evidence is not independent runtime or scientific verification.'}

    @router.get('/library/outputs/{output_type}/{oid}/preview')
    def output_preview(output_type:str,oid:str,request:Request):
        who=actor(request)
        with connection() as db:result=output_document(db,who,output_type,oid)
        text=json.dumps(result,indent=2,ensure_ascii=False)
        return {'filename':result['title']+'.json','preview':text[:24000],
            'truncated':len(text)>24000,'has_text':True,'notice':'Saved original output snapshot. Integrity verified; scientific and runtime correctness not established.'}

    @router.get('/library/outputs/{output_type}/{oid}/download')
    def output_download(output_type:str,oid:str,request:Request):
        who=actor(request)
        with connection() as db:result=output_document(db,who,output_type,oid)
        name=re.sub(r'[^A-Za-z0-9._-]','_',result['title'])[:90] or 'output'
        return PlainTextResponse(json.dumps(result,indent=2,ensure_ascii=False),media_type='application/json',
             headers={'Content-Disposition':f'attachment; filename="{name}.json"','Cache-Control':'no-store'})
