"""Read-only Afterlight consistency report for NESSON 96-100.

Does not import app.main, initialize tables, read questions/evidence, or mutate data.
Use while NESSON is stopped for a stable snapshot.
"""
import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path


def assess(db_path):
    db_path=Path(db_path).expanduser().resolve()
    if not db_path.is_file():
        return {'status':'attention_required','error':'database_missing','database':str(db_path)}
    con=sqlite3.connect(db_path.as_uri()+'?mode=ro',uri=True)
    con.row_factory=sqlite3.Row
    try:
        integrity=con.execute('PRAGMA quick_check').fetchone()[0]
        required=('projects','afterlight_jobs','afterlight_retry_links','afterlight_schedules','afterlight_notices')
        tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing=sorted(set(required)-tables)
        if missing:
            return {'status':'attention_required','database':str(db_path),'sqlite_quick_check':integrity,'missing_tables':missing}
        jobs=[dict(r) for r in con.execute('SELECT id,project_id,status FROM afterlight_jobs')]
        links=[dict(r) for r in con.execute('SELECT attempt_id,project_id,parent_job_id FROM afterlight_retry_links')]
        schedules=[dict(r) for r in con.execute('SELECT id,project_id,enabled,interval_minutes,last_job_id FROM afterlight_schedules')]
        notices=[dict(r) for r in con.execute('SELECT id,project_id,job_id,status FROM afterlight_notices')]
        projects={r[0] for r in con.execute('SELECT id FROM projects')}
        jobs_by_id={j['id']:j for j in jobs}
        errors=[]
        for j in jobs:
            if j['project_id'] not in projects:errors.append('job_missing_project')
        for l in links:
            child=jobs_by_id.get(l['attempt_id']); parent=jobs_by_id.get(l['parent_job_id'])
            if not child or not parent:errors.append('retry_missing_job')
            elif not (child['project_id']==parent['project_id']==l['project_id']):errors.append('retry_cross_project')
        attempts_by_parent=Counter(l['parent_job_id'] for l in links)
        if any(n>1 for n in attempts_by_parent.values()):errors.append('duplicate_parent_retry')
        for s in schedules:
            if s['project_id'] not in projects: errors.append('schedule_missing_project')
            if s['last_job_id']:
                j=jobs_by_id.get(s['last_job_id'])
                if not j or j['project_id']!=s['project_id']:errors.append('schedule_missing_or_cross_project_job')
            if not 15<=s['interval_minutes']<=10080:errors.append('schedule_interval_outside_limits')
        for n in notices:
            j=jobs_by_id.get(n['job_id'])
            if not j or j['project_id']!=n['project_id']:errors.append('notice_missing_or_cross_project_job')
        status_counts=dict(sorted(Counter(j['status'] for j in jobs).items()))
        return {'status':'pass' if integrity=='ok' and not errors else 'attention_required',
                'database':str(db_path),'sqlite_quick_check':integrity,
                'counts':{'jobs':len(jobs),'retry_links':len(links),'schedules':len(schedules),'notices':len(notices)},
                'job_status_counts':status_counts,'issues':dict(sorted(Counter(errors).items())),
                'cautions':['This is a consistency audit, not a live scheduler/worker benchmark.',
                            'Queued/running records can be normal while NESSON is active; stop the server before auditing.',
                            'No question text, evidence content, session tokens or model responses are collected.']}
    finally:con.close()


def main():
    p=argparse.ArgumentParser(description='Read-only audit of Afterlight records.')
    p.add_argument('--data-dir',default='data')
    p.add_argument('--strict',action='store_true')
    args=p.parse_args()
    result=assess(Path(args.data_dir)/'nesson.sqlite3')
    print(json.dumps(result,indent=2))
    if args.strict and result['status']!='pass':sys.exit(1)

if __name__=='__main__':main()
