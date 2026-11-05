"""Offline/read-only NESSON data integrity report. Never modifies user data.
Run: uv run python nesson_integrity.py --data-dir data [--strict]
Does not expose file contents, credentials, or raw evidence paths in reports.
"""
import argparse, hashlib, json, os, sqlite3
from contextlib import closing
from pathlib import Path

def assess(data_dir, check_hashes=True):
    data=Path(data_dir).expanduser().resolve()
    db_path=data/'nesson.sqlite3'
    report={'database_present':db_path.is_file(), 'sqlite_integrity':None,
            'sqlite_foreign_key_violations':None, 'file_records_checked':0,
            'missing_files':0,'unsafe_file_paths':0,'hash_mismatches':0,
            'unreadable_files':0,'hash_check_enabled':bool(check_hashes),
            'issues':[], 'status':'incomplete'}
    if not db_path.is_file():
        report['issues'].append('Database file is missing');return report
    try:
        # Read-only URI avoids creating/modifying the database or its sidecars.
        with closing(sqlite3.connect(db_path.as_uri()+'?mode=ro',uri=True,timeout=10)) as db:
            integrity=db.execute('PRAGMA integrity_check').fetchone()[0]
            report['sqlite_integrity']=integrity
            if integrity!='ok':report['issues'].append('SQLite integrity_check returned a non-OK result')
            report['sqlite_foreign_key_violations']=len(db.execute('PRAGMA foreign_key_check').fetchall())
            if report['sqlite_foreign_key_violations']:
                report['issues'].append('SQLite foreign key check found violations')
            tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'files' not in tables:
                report['issues'].append('Evidence files table missing')
            else:
                storage=(data/'files').resolve()
                for fid,path,expected in db.execute('SELECT id,storage_path,sha256 FROM files'):
                    report['file_records_checked']+=1
                    candidate=Path(path).resolve()
                    if not candidate.is_relative_to(storage) or candidate.is_symlink():
                        report['unsafe_file_paths']+=1;continue
                    if not candidate.is_file():report['missing_files']+=1;continue
                    if check_hashes:
                        try:
                            dig=hashlib.sha256()
                            with candidate.open('rb') as f:
                                for b in iter(lambda:f.read(1024*1024),b''):dig.update(b)
                            if dig.hexdigest()!=expected:report['hash_mismatches']+=1
                        except OSError:report['unreadable_files']+=1
        for key in ('missing_files','unsafe_file_paths','hash_mismatches','unreadable_files'):
            if report[key]:report['issues'].append(f'{key}: {report[key]}')
        report['status']='pass' if not report['issues'] else 'attention_required'
    except (sqlite3.DatabaseError,OSError) as exc:
        report['issues'].append('Unable to complete SQLite audit: '+type(exc).__name__)
        report['status']='incomplete'
    report['limitations']=['Integrity and SHA-256 checks do not prove the source information is authentic.',
        'Database can change while NESSON is running; stop NESSON for a consistent audit.',
        'Application-wide semantic correctness, uploads not indexed in the database, and external provider results are not verified.']
    return report

def main():
    p=argparse.ArgumentParser(description='Read-only local database and evidence integrity audit')
    p.add_argument('--data-dir',default=os.environ.get('NESSON_DATA_DIR','data'))
    p.add_argument('--skip-hashes',action='store_true')
    p.add_argument('--strict',action='store_true',help='Exit nonzero if report is not PASS')
    args=p.parse_args()
    result=assess(args.data_dir,not args.skip_hashes)
    print(json.dumps(result,indent=2))
    if args.strict and result['status']!='pass':raise SystemExit(2)
if __name__=='__main__':main()
