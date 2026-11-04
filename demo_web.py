"""Loopback-only fixture showcase. No GitHub API, dotenv, or application import."""
import difflib
import json
from pathlib import Path
import tempfile
import threading

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from analyzers.semgrep_runner import run_semgrep
from demo_behavior import run_behavioral
from demo_rules import SHOWCASE_RULESET as OFFLINE_RULESET

ROOT = Path(__file__).resolve().parent / 'demo'
FIXTURES = {'vulnerable': ROOT / 'showcase/vulnerable.py', 'fixed': ROOT / 'showcase/fixed.py'}
SCENARIOS = {
    'sql': FIXTURES,
    'tls': {variant: ROOT / ('showcase/tls_' + variant + '.py') for variant in ('vulnerable', 'fixed')},
    'command': {variant: ROOT / ('showcase/command_' + variant + '.py') for variant in ('vulnerable', 'fixed')},
    'yaml': {variant: ROOT / ('showcase/yaml_' + variant + '.py') for variant in ('vulnerable', 'fixed')},
}
CATALOG = json.loads((ROOT / 'catalog.json').read_text())
SCENARIOS.update({key: {variant: ROOT / f'showcase/{key}_{variant}.py' for variant in ('vulnerable', 'fixed')} for key in CATALOG if key not in SCENARIOS})
SCAN_LOCK = threading.Lock()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost'])


@app.middleware('http')
async def local_security(request: Request, call_next):
    if request.method == 'POST':
        # Custom header forces cross-origin browsers to preflight; no CORS is enabled.
        # Also enforce the exact local origin, preventing hostile browser sites from scanning.
        if (request.headers.get('origin') != f'http://{request.headers.get("host")}'
                or request.headers.get('x-prsec-demo') != '1'):
            return JSONResponse({'detail': 'Local demo origin required'}, status_code=403)
    response = await call_next(request)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    return response


@app.get('/')
def index():
    return FileResponse(ROOT / 'ui/index.html')


@app.get('/ui/{name}')
def asset(name: str):
    if name not in {'demo.css', 'demo.js'}:
        raise HTTPException(404)
    return FileResponse(ROOT / 'ui' / name)


@app.get('/api/fixtures')
@app.get('/api/fixtures/{scenario}')
def fixtures(scenario: str = 'sql'):
    if scenario not in SCENARIOS:
        raise HTTPException(404, 'Unknown bundled scenario')
    source = {key: path.read_text() for key, path in SCENARIOS[scenario].items()}
    return {'source': source, 'highlights': CATALOG.get(scenario, {}).get('highlights', {}),
        'review_mode': CATALOG.get(scenario, {}).get('mode', 'scan'), 'diff': ''.join(difflib.unified_diff(
        source['vulnerable'].splitlines(True), source['fixed'].splitlines(True),
        fromfile='proposed/' + scenario + '.py', tofile='fixed/' + scenario + '.py')),
        'provenance': 'Bundled trusted fixtures; GitHub PR and Check states are simulated.'}


@app.post('/api/scan/{variant}')
@app.post('/api/scan/{scenario}/{variant}')
def scan(variant: str, scenario: str = 'sql'):
    if scenario not in SCENARIOS or variant not in SCENARIOS[scenario]:
        raise HTTPException(404, 'Only bundled fixtures can be scanned')
    selected = SCENARIOS[scenario][variant]
    if not SCAN_LOCK.acquire(blocking=False):
        raise HTTPException(429, 'A scan is already running. Try again when it finishes.')
    try:
        if CATALOG.get(scenario, {}).get('mode') == 'behavioral':
            result = run_behavioral(scenario, variant)
            return {**result, 'findings': [], 'provenance': 'Actual bounded behavioral test of an authored fixture with synthetic adapters only. No real services or GitHub actions.'}
        # Fix scan input and rules server-side; no URL, path, source, or config from clients.
        with tempfile.TemporaryDirectory(prefix='prsec_showcase_') as temporary:
            config = Path(temporary) / 'rules.yaml'
            config.write_text(OFFLINE_RULESET)
            findings = run_semgrep([selected.name], str(selected.parent),
                                   config=str(config), timeout_s=30)
        return {'status': 'failure' if findings else 'success', 'engine': 'semgrep', 'findings': findings,
                'provenance': 'Live local scanner result. No GitHub Check or comment was sent.',
                'variant': variant, 'scenario': scenario}
    except Exception:
        # Do not expose command output, host paths, environment, or secrets to browsers.
        return JSONResponse({'status': 'error', 'findings': [],
            'provenance': 'Local check failed; no passing verdict was issued.',
            'message': 'Local check unavailable, timed out, or returned incomplete output. No passing verdict was issued.'},
            status_code=503)
    finally:
        SCAN_LOCK.release()


if __name__ == '__main__':
    import os
    import uvicorn
    # The demo does not need application tokens, dotenv, or external scanner configuration.
    allowed = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'SYSTEMROOT') if key in os.environ}
    os.environ.clear()
    os.environ.update(allowed)
    os.environ.update(PRSEC_MODE='local', PRSEC_SCANNER_BACKEND='local', PRSEC_LOAD_DOTENV='0')
    uvicorn.run(app, host='127.0.0.1', port=8765, access_log=False)
