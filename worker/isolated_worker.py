"""Offline operator-run NESSON worker for a dedicated Linux Docker host.

Not installed in app/ and never invoked from the NESSON FastAPI server.
Uses only Python stdlib. Does NOT automate submission to NESSON.
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

MAX_ARCHIVE = 2 * 1024 * 1024
MAX_LOG_BYTES = 16000  # each stream; combined signed report must stay below NESSON 48 KB cap
MAX_WALL = 120
IMAGE_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._:/@-]*@sha256:[0-9a-f]{64}$')


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def sha(b):
    return hashlib.sha256(b).hexdigest()


def validate(payload):
    if not isinstance(payload, dict) or not {'handoff_id','challenge','request_id','manifest','manifest_sha256','artifact_sha256','artifact_zip_base64'} <= set(payload):
        raise ValueError('Invalid handoff')
    for field in ('handoff_id','request_id'):
        if not isinstance(payload[field],str) or not re.fullmatch('[0-9a-f]{32}',payload[field]):
            raise ValueError('Invalid identifier')
    if not isinstance(payload['challenge'],str) or not (30 <= len(payload['challenge']) <= 128):
        raise ValueError('Invalid challenge')
    manifest = payload['manifest']
    if not isinstance(manifest,dict) or sha(canonical(manifest)) != payload['manifest_sha256']:
        raise ValueError('Manifest hash mismatch')
    if manifest.get('version') != 1 or manifest.get('task') != 'repository_tests' or manifest.get('provider') != 'unconfigured' or manifest.get('execution_allowed') is not False:
        raise ValueError('Unsupported manifest')
    if manifest.get('selector') not in ('unittest','pytest'):
        raise ValueError('Unsupported selector')
    if manifest.get('artifact_sha256') != payload['artifact_sha256']:
        raise ValueError('Artifact does not match manifest')
    p = manifest.get('policy', {})
    required = {'network':'disabled', 'filesystem':'ephemeral-readonly-source', 'max_wall_seconds':120,
                'max_cpu_seconds':60,'max_memory_mb':512,'max_output_bytes':65536,
                'allow_host_secrets':False,'privileged':False}
    if p != required:
        raise ValueError('Policy mismatch')
    try:
        raw = base64.b64decode(payload['artifact_zip_base64'], validate=True)
    except (binascii.Error, ValueError):
        raise ValueError('Invalid ZIP encoding') from None
    if not raw or len(raw) > MAX_ARCHIVE or sha(raw) != payload['artifact_sha256']:
        raise ValueError('ZIP mismatch or size violation')
    return manifest, raw


def cap_bytes(s):
    return s[:MAX_LOG_BYTES].decode('utf-8', 'replace')


def docker_command(image, hostdir, selector):
    if not IMAGE_PATTERN.fullmatch(image):
        raise ValueError('Docker image must be pinned to a verified sha256 digest')
    if selector not in ('pytest', 'unittest'):
        raise ValueError('Invalid selector')
    # stdout and stderr are captured. OCI isolation is supplied by the remote Docker daemon.
    # Host operator must independently harden daemon, kernel, network and resource policy.
    return ['docker','run','--rm','--pull=never', '--network=none', '--read-only',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit=64',
            '--memory=512m', '--memory-swap=512m', '--cpus=1', '--ulimit=cpu=60:60',
            f'--user={getattr(os,"getuid",lambda:65534)()}:{getattr(os,"getgid",lambda:65534)()}', '--workdir=/work',
            '--tmpfs=/work:rw,nosuid,nodev,exec,size=64m,mode=1777',
            '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',
            f'--mount=type=bind,src={hostdir},dst=/input,readonly',
            '--env=PYTHONDONTWRITEBYTECODE=1', '--env=PYTEST_DISABLE_PLUGIN_AUTOLOAD=1',
            image, 'python', '-I', '/input/runner.py', selector]


def perform(handoff, *, image, secret, docker_run=subprocess.run):
    manifest, archive = validate(handoff)
    if not isinstance(secret,bytes) or not (48 <= len(secret) <= 256):
        raise ValueError('Missing or invalid independently provisioned worker signing key')
    if not sys.platform.startswith('linux'):
        raise RuntimeError('Isolated execution requires a dedicated Linux worker host')
    if os.getuid() == 0:
        raise RuntimeError('Worker must not run as root')
    selector=manifest['selector']
    start=time.monotonic()
    with tempfile.TemporaryDirectory(prefix='nesson-isolated-') as t:
        root=Path(t)
        (root/'repository.zip').write_bytes(archive)
        (root/'runner.py').write_bytes((Path(__file__).parent/'runner.py').read_bytes())
        os.chmod(root,0o700)
        os.chmod(root/'repository.zip',0o600)
        os.chmod(root/'runner.py',0o600)
        args=docker_command(image,str(root),selector)
        try:
            process=docker_run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.DEVNULL, timeout=MAX_WALL, check=False)
            code=process.returncode
            if code in (125,126,127) or code < 0 or code>255:
                raise RuntimeError('Container runtime/startup error; no test result issued')
            out=process.stdout or b''
            err=process.stderr or b''
        except subprocess.TimeoutExpired as exc:
            code=124
            out=exc.stdout or b''
            err=(exc.stderr or b'')+b'\nWorker timeout; container must be independently checked for cleanup.'
        except OSError as exc:
            # Runtime unavailability is not represented as a test failure or valid execution result.
            raise RuntimeError('Docker container runtime unavailable') from exc
    elapsed=min(round((time.monotonic()-start)*1000), MAX_WALL*1000)
    report={'schema':1,'handoff_id':handoff['handoff_id'], 'request_id':handoff['request_id'],
            'challenge':handoff['challenge'], 'manifest_sha256':handoff['manifest_sha256'],
            'artifact_sha256':handoff['artifact_sha256'], 'selector':selector,
            'exit_code':code, 'stdout':cap_bytes(out), 'stderr':cap_bytes(err),
            'elapsed_ms':elapsed, 'worker_label':'isolated-docker-linux-v1'}
    signature=hmac.new(secret,canonical(report),hashlib.sha256).hexdigest()
    return {'payload':report,'signature':signature}


def main():
    ap=argparse.ArgumentParser(description='Dedicated offline NESSON Docker worker')
    ap.add_argument('--handoff',required=True,help='Private JSON saved from approved NESSON handoff')
    ap.add_argument('--output',required=True,help='Private result JSON; submit separately through authorized NESSON endpoint')
    ap.add_argument('--image',required=True,help='Operator-reviewed image pinned as repository@sha256:digest, with python and pytest installed')
    ap.add_argument('--operator-authorized',action='store_true',help='Confirms separate operator authorization on isolated host')
    args=ap.parse_args()
    if not args.operator_authorized:
        ap.error('Explicit operator authorization required; no execution occurred')
    key=os.environ.get('NESSON_EXTERNAL_WORKER_HMAC_KEY','').encode()
    try:
        data=json.loads(Path(args.handoff).read_text(encoding='utf-8'))
        response=perform(data,image=args.image,secret=key)
        output=Path(args.output)
        if output.exists():raise RuntimeError('Will not overwrite an existing worker result')
        fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(response,f,sort_keys=True,indent=2)
        print('Report saved. Submission and independent review are separate steps.')
    except Exception as exc:
        print('Worker refused operation: '+str(exc),file=sys.stderr)
        raise SystemExit(2)

if __name__=='__main__':main()
