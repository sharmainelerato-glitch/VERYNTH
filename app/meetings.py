"""Workspace-scoped meeting signalling. Single-process prototype; not a production SFU."""
import secrets, time, threading
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

_lock=threading.RLock()
_rooms={}
_TTL=7200
class Signal(BaseModel):
    recipient:str=Field(min_length=1,max_length=80)
    kind:str=Field(pattern='^(offer|answer|ice|leave)$')
    payload:dict=Field(default_factory=dict)

def register_meetings(app,connection,actor,member):
    router=APIRouter(prefix='/api/team/workspaces/{wid}/meetings',tags=['meetings'])
    def check(wid,request):
        who=actor(request)
        with connection() as db:member(db,wid,who)
        return who
    def room(wid,rid):
        key=(wid,rid)
        with _lock:
            item=_rooms.get(key)
            if not item or time.time()-item['created']>_TTL:raise HTTPException(404,'Meeting expired or not found')
            return item
    @router.post('')
    def create(wid:str,request:Request):
        who=check(wid,request)
        rid=secrets.token_urlsafe(18)
        with _lock:_rooms[(wid,rid)]={'created':time.time(),'owner':who['id'],'peers':{},'queue':{}}
        return {'id':rid,'url':f'/static/verynth-meeting.html?workspace={wid}&meeting={rid}','expires_in':_TTL}
    @router.post('/{rid}/join')
    def join(wid:str,rid:str,request:Request):
        who=check(wid,request)
        with _lock:
            r=room(wid,rid)
            # Each browser tab gets an independent ephemeral participant ID.
            pid=secrets.token_urlsafe(16)
            peers=[{'id':p,'name':v['name']} for p,v in r['peers'].items()]
            r['peers'][pid]={'user':who['id'],'name':who['display_name'],'last':time.time()}
            r['queue'][pid]=[]
            return {'participant_id':pid,'peers':peers,'name':who['display_name']}
    def verified(wid,rid,pid,request):
        who=check(wid,request);r=room(wid,rid)
        p=r['peers'].get(pid)
        if not p or p['user']!=who['id']:raise HTTPException(403,'Not a meeting participant')
        return r
    @router.get('/{rid}/poll')
    def poll(wid:str,rid:str,pid:str,request:Request):
        with _lock:
            r=verified(wid,rid,pid,request)
            r['peers'][pid]['last']=time.time()
            for other,p in list(r['peers'].items()):
                if time.time()-p['last']>35:
                    del r['peers'][other];r['queue'].pop(other,None)
                    for q in r['queue'].values():q.append({'kind':'leave','from':other,'payload':{}})
            messages=r['queue'][pid][:];r['queue'][pid].clear()
            return {'messages':messages,'peers':[{'id':k,'name':v['name']} for k,v in r['peers'].items() if k!=pid]}
    @router.post('/{rid}/signal')
    def signal(wid:str,rid:str,pid:str,body:Signal,request:Request):
        with _lock:
            r=verified(wid,rid,pid,request)
            if body.recipient not in r['peers']:raise HTTPException(404,'Recipient unavailable')
            if len(str(body.payload))>200000:raise HTTPException(413,'Signal too large')
            if len(r['queue'][body.recipient])>=150:raise HTTPException(429,'Recipient queue full')
            r['queue'][body.recipient].append({'kind':body.kind,'from':pid,'payload':body.payload})
            return {'ok':True}
    @router.post('/{rid}/leave')
    def leave(wid:str,rid:str,pid:str,request:Request):
        with _lock:
            r=verified(wid,rid,pid,request)
            r['peers'].pop(pid,None);r['queue'].pop(pid,None)
            for q in r['queue'].values():q.append({'kind':'leave','from':pid,'payload':{}})
        return {'ok':True}
    app.include_router(router)
