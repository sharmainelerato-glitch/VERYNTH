"""Read-only local dependency inventory; no network calls or automatic changes."""
import importlib.metadata as metadata
import json, platform, sys

def report():
    names=('fastapi','starlette','httpx','httpx2','anyio','pydantic','uvicorn','python-dotenv')
    versions={}
    for n in names:
        try:versions[n]=metadata.version(n)
        except metadata.PackageNotFoundError:versions[n]=None
    return {'python':sys.version.split()[0],'platform':platform.platform(),
            'dependencies':versions,'notes':[
                'Read-only inventory. No dependencies were installed or upgraded.',
                'Deprecation warnings require a tested dependency update; this report cannot certify compatibility.',
                'Check uv.lock and run the complete regression suite before changing versions.']}
if __name__=='__main__':print(json.dumps(report(),indent=2))
