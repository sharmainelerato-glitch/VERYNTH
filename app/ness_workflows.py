"""VERYNTH evidence-domain discovery and bounded read-only workflow execution.
No model inference, provider calls, code execution, file writes, or autonomous approvals.
"""
import json
import re
import sqlite3
import uuid
from fastapi import HTTPException
from pydantic import BaseModel, Field

DOMAINS = {
 'software': ('code','python','javascript','typescript','repository','debug','patch','function','api','programming','stack trace','git','test failure'),
 'cybersecurity': ('security','vulnerability','cve','threat','malware','incident','soc','attack','phishing','authentication','network','exploit'),
 'finance': ('finance','invoice','revenue','budget','balance','cashflow','cash flow','investment','profit','expense','accounting','forecast'),
 'science': ('science','experiment','hypothesis','laboratory','chemistry','biology','physics','research','measurement'),
 'robotics': ('robot','robotics','sensor','actuator','kinematics','trajectory','motor','navigation','lidar','battery'),
 'earth_sciences': ('geology','climate','earthquake','flood','weather','terrain','geospatial','satellite','soil','environment'),
 'legal': ('legal','contract','court','case law','statute','evidence','jurisdiction','compliance'),
 'operations': ('meeting','decision','project','task','workflow','schedule','risk','planning'),
}
SUFFIX_DOMAINS={'.py':'software','.js':'software','.ts':'software','.tsx':'software','.jsx':'software','.sql':'software','.ipynb':'software','.pcap':'cybersecurity','.tf':'software','.csv':'finance'}
TOOLS = {
 'list_project_files': 'List uploaded file names, sizes and extraction status',
 'search_project_evidence': 'Search extracted project evidence for relevant text',
 'list_intelligence_cases': 'Read saved intelligence investigations',
 'get_reliability_overview': 'Read saved reliability and processing records',
 'list_reality_twins': 'Read existing scenario models',
 'get_engineering_verification_plan': 'Read the existing engineering verification plan',
 'list_ai_council_reports': 'Read saved AI Council reports',
}
class PlanRequest(BaseModel):
 question: str = Field(min_length=2,max_length=2000)
class ExecuteRequest(BaseModel):
 plan_id: str = Field(min_length=32,max_length=32)

def detect(question, files):
 text=question.lower()
 corpus=text+' '+ ' '.join(str(f['filename']).lower() for f in files[:60])
 scores={}
 for domain,terms in DOMAINS.items():
  scores[domain]=sum(3 if re.search(r'(?<!\w)'+re.escape(t)+r'(?!\w)',text) else 0 for t in terms)
  scores[domain]+=sum(1 for t in terms if re.search(r'(?<!\w)'+re.escape(t)+r'(?!\w)',corpus))
 for f in files[:60]:
  for suffix,domain in SUFFIX_DOMAINS.items():
   if str(f['filename']).lower().endswith(suffix): scores[domain]+=2
 ranked=sorted(scores,key=lambda d:(-scores[d],d))
 return [{'domain':d,'score':scores[d]} for d in ranked if scores[d]>0][:3] or [{'domain':'general','score':0}]

def selected_tools(question,domains):
 q=question.lower(); ds={x['domain'] for x in domains}
 result=['list_project_files','search_project_evidence']
 if 'software' in ds or 'cybersecurity' in ds: result.append('get_engineering_verification_plan')
 if 'legal' in ds or 'cybersecurity' in ds or 'investigat' in q:result.append('list_intelligence_cases')
 if 'robotics' in ds or 'earth_sciences' in ds or 'scenario' in q or 'simulat' in q:result.append('list_reality_twins')
 if 'reliab' in q or 'status' in q or 'monitor' in q:result.append('get_reliability_overview')
 if 'council' in q or 'perspective' in q or 'compare' in q:result.append('list_ai_council_reports')
 return list(dict.fromkeys(result))[:7]

def install_ness_workflows(app, connection, project_or_404, now, ness_read_tool):
 with connection() as db:
  db.execute("""CREATE TABLE IF NOT EXISTS ness_workflow_plans(id TEXT PRIMARY KEY,project_id TEXT NOT NULL,question TEXT NOT NULL,domains_json TEXT NOT NULL,tools_json TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,executed_at TEXT)""")
  db.execute("""CREATE TABLE IF NOT EXISTS ness_workflow_results(id TEXT PRIMARY KEY,plan_id TEXT NOT NULL,project_id TEXT NOT NULL,tool_name TEXT NOT NULL,result_json TEXT NOT NULL,created_at TEXT NOT NULL)""")

 @app.post('/api/projects/{pid}/ness-workflows/plan')
 def plan(pid:str,body:PlanRequest):
  project_or_404(pid)
  question=body.question.strip()
  if len(question)<2:raise HTTPException(400,'Enter a question')
  with connection() as db:
   files=[dict(r) for r in db.execute('SELECT filename,extract_status FROM files WHERE project_id=? ORDER BY created_at DESC LIMIT 100',(pid,))]
  domains=detect(question,files);tools=selected_tools(question,domains)
  record={'id':uuid.uuid4().hex,'project_id':pid,'question':question,'domains_json':json.dumps(domains),'tools_json':json.dumps(tools),'status':'proposed','created_at':now()}
  with connection() as db:db.execute('INSERT INTO ness_workflow_plans(id,project_id,question,domains_json,tools_json,status,created_at) VALUES (:id,:project_id,:question,:domains_json,:tools_json,:status,:created_at)',record)
  return {'plan_id':record['id'],'question':question,'domains':domains,'tools':[{'name':t,'description':TOOLS[t]} for t in tools],'status':'proposed','requires_confirmation':True,'limits':'Heuristic domain detection; read-only saved records and extracted text. No new AI analysis, simulation, modification, or external action.'}

 @app.post('/api/projects/{pid}/ness-workflows/execute')
 def execute(pid:str,body:ExecuteRequest):
  project_or_404(pid)
  with connection() as db:
   plan=db.execute('SELECT * FROM ness_workflow_plans WHERE id=? AND project_id=?',(body.plan_id,pid)).fetchone()
   if not plan:raise HTTPException(404,'Plan not found in this project')
   if plan['status']!='proposed':raise HTTPException(409,'Plan has already been executed or is unavailable')
   changed=db.execute("UPDATE ness_workflow_plans SET status='running' WHERE id=? AND project_id=? AND status='proposed'",(body.plan_id,pid))
   if changed.rowcount!=1:raise HTTPException(409,'Plan already claimed')
  tools=json.loads(plan['tools_json']); outcomes=[]
  for name in tools:
   if name not in TOOLS:continue
   args={'query':plan['question'][:120]} if name=='search_project_evidence' else {}
   try:result=ness_read_tool(pid,name,args)
   except Exception as exc:result={'error':'Tool unavailable','error_type':type(exc).__name__}
   encoded=json.dumps(result,ensure_ascii=False,default=str)
   if len(encoded)>30000:encoded=json.dumps({'truncated':True,'preview':encoded[:28000]})
   outcomes.append({'name':name,'result':json.loads(encoded)})
   with connection() as db:db.execute('INSERT INTO ness_workflow_results VALUES (?,?,?,?,?,?)',(uuid.uuid4().hex,body.plan_id,pid,name,encoded,now()))
  with connection() as db:db.execute("UPDATE ness_workflow_plans SET status='completed',executed_at=? WHERE id=? AND project_id=?",(now(),body.plan_id,pid))
  return {'plan_id':body.plan_id,'status':'completed','results':outcomes,'new_ai_analysis_performed':False,'changes_applied':False}

 @app.get('/api/projects/{pid}/ness-workflows/history')
 def history(pid:str):
  project_or_404(pid)
  with connection() as db:
   plans=[dict(r) for r in db.execute('SELECT id,question,domains_json,tools_json,status,created_at,executed_at FROM ness_workflow_plans WHERE project_id=? ORDER BY created_at DESC LIMIT 30',(pid,))]
  for p in plans:p['domains']=json.loads(p.pop('domains_json'));p['tools']=json.loads(p.pop('tools_json'))
  return {'items':plans}

 @app.get('/api/projects/{pid}/ness-workflows/{plan_id}')
 def detail(pid:str,plan_id:str):
  project_or_404(pid)
  with connection() as db:
   p=db.execute('SELECT * FROM ness_workflow_plans WHERE project_id=? AND id=?',(pid,plan_id)).fetchone()
   if not p:raise HTTPException(404,'Plan not found')
   rows=db.execute('SELECT tool_name,result_json,created_at FROM ness_workflow_results WHERE project_id=? AND plan_id=? ORDER BY rowid',(pid,plan_id)).fetchall()
  return {'plan_id':plan_id,'question':p['question'],'status':p['status'],'domains':json.loads(p['domains_json']),'results':[{'name':r['tool_name'],'result':json.loads(r['result_json']),'created_at':r['created_at']} for r in rows]}
