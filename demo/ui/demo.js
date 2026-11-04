'use strict';
const $ = id => document.getElementById(id);
let scenario = 'sql';
const scenarios = {"access": {"name": "Invoice ownership", "category": "A01:2025 Broken Access Control", "source": "https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/", "file": "access.py", "title": "Review: Invoice ownership", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "A changed invoice ID could expose another customer’s bill.", "fixTitle": "What the fix changes", "fix": "Check ownership on the server before returning an invoice. The current user must come from a trusted authenticated session.", "action": "View proposed fix →", "finding": "Invoice ownership needs attention", "instruction": "Check ownership on the server before returning an invoice. The current user must come from a trusted authenticated session.", "limit": "Try owner, different user, anonymous user and missing invoice against every read/update route. Verify tenant isolation and server-side identity.", "mode": "behavioral", "highlights": {"vulnerable": [4], "fixed": [4, 5]}}, "config": {"name": "Debug responses", "category": "A02:2025 Security Misconfiguration", "source": "https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/", "file": "config.py", "title": "Review: Debug responses", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "Debug mode can expose detailed exception traces to visitors.", "fixTitle": "What the fix changes", "fix": "Disable debug responses and keep diagnostics in protected server logs.", "action": "View proposed fix →", "finding": "Debug responses needs attention", "instruction": "Disable debug responses and keep diagnostics in protected server logs.", "limit": "The rule matches literal FastAPI(debug=True) only. Inspect deployed settings and trigger a controlled exception to confirm no diagnostic data leaks.", "mode": "scan", "highlights": {"vulnerable": [4], "fixed": [4]}}, "supply": {"name": "Dependency release gates", "category": "A03:2025 Software Supply Chain Failures", "source": "https://top10.owasp.org/2025/A03_2025-Software_Supply_Chain_Failures/", "file": "supply.py", "title": "Review: Dependency release gates", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "Untracked, unaudited dependencies can introduce vulnerable or compromised code into a release.", "fixTitle": "What the fix changes", "fix": "Use a reviewed hash-locked dependency set, provenance checks, current audits and an inventory. The fixed fixture describes required pipeline gates, not an implemented build system.", "action": "View proposed fix →", "finding": "Dependency release gates needs attention", "instruction": "Use a reviewed hash-locked dependency set, provenance checks, current audits and an inventory. The fixed fixture describes required pipeline gates, not an implemented build system.", "limit": "Verify the actual lock, hashes, provenance identities, transitive audit, SBOM and update process. Fail each gate deliberately; hashing alone does not prove a dependency safe.", "mode": "behavioral", "highlights": {"vulnerable": [3], "fixed": [5, 6, 7, 8, 9]}}, "tls": {"name": "TLS certificate verification", "category": "A04:2025 Cryptographic Failures", "source": "https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/", "file": "fetch_status.py", "title": "Review: TLS certificate verification", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "verify=False disables certificate-chain and hostname checks. An intercepting attacker could impersonate the HTTPS server even though traffic is encrypted.", "fixTitle": "What the fix changes", "fix": "Use the Requests default certificate verification or explicit verify=True. Keep a timeout; it does not replace identity validation.", "action": "View proposed fix →", "finding": "TLS certificate verification needs attention", "instruction": "Use the Requests default certificate verification or explicit verify=True. Keep a timeout; it does not replace identity validation.", "limit": "The rule checks literal verify=False in requests.get/post/request only. Validate the actual trust store and certificate failure behavior separately; no network request runs here.", "mode": "scan", "highlights": {"vulnerable": [8], "fixed": [8]}}, "sql": {"name": "SQL parameter binding", "category": "A05:2025 Injection", "source": "https://top10.owasp.org/2025/A05_2025-Injection/", "file": "customer_lookup.py", "title": "Review: SQL parameter binding", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "A customer name concatenated into SQL can change the database instruction.", "fixTitle": "What the fix changes", "fix": "Use a query placeholder with a separately bound value so input stays data.", "action": "View proposed fix →", "finding": "SQL parameter binding needs attention", "instruction": "Use a query placeholder with a separately bound value so input stays data.", "limit": "This rule targets concatenation directly inside execute. It does not cover every query builder, dynamic identifier or injection path.", "mode": "scan", "highlights": {"vulnerable": [4], "fixed": [4]}}, "design": {"name": "One coupon per customer", "category": "A06:2025 Insecure Design", "source": "https://top10.owasp.org/2025/A06_2025-Insecure_Design/", "file": "design.py", "title": "Review: One coupon per customer", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "Without a redemption limit, a customer can repeatedly claim the same credit, including through concurrent requests.", "fixTitle": "What the fix changes", "fix": "Define a one-redemption invariant and enforce it atomically with credit issuance. The fixed fixture illustrates a transaction and uniqueness contract.", "action": "View proposed fix →", "finding": "One coupon per customer needs attention", "instruction": "Define a one-redemption invariant and enforce it atomically with credit issuance. The fixed fixture illustrates a transaction and uniqueness contract.", "limit": "Threat-model abuse and test concurrent/replayed requests, rollback and cross-account rules against the real database. A method name cannot establish atomicity.", "mode": "behavioral", "highlights": {"vulnerable": [4], "fixed": [5, 6, 7, 8]}}, "auth": {"name": "Session rotation at login", "category": "A07:2025 Authentication Failures", "source": "https://top10.owasp.org/2025/A07_2025-Authentication_Failures/", "file": "auth.py", "title": "Review: Session rotation at login", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "Reusing the pre-login session identifier can let someone who knows that identifier inherit the authenticated session.", "fixTitle": "What the fix changes", "fix": "Rotate the session identifier after verified login and invalidate the previous identifier atomically. The session service must implement this contract.", "action": "View proposed fix →", "finding": "Session rotation at login needs attention", "instruction": "Rotate the session identifier after verified login and invalidate the previous identifier atomically. The session service must implement this contract.", "limit": "Confirm old sessions fail, new identifiers are unpredictable, cookies are Secure/HttpOnly with appropriate SameSite, and expiry/logout work. Also assess MFA and login abuse controls.", "mode": "behavioral", "highlights": {"vulnerable": [5, 6], "fixed": [6]}}, "yaml": {"name": "Safe YAML deserialization", "category": "A08:2025 Software or Data Integrity Failures", "source": "https://top10.owasp.org/2025/A08_2025-Software_or_Data_Integrity_Failures/", "file": "read_settings.py", "title": "Review: Safe YAML deserialization", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "An unsafe YAML loader can construct Python objects from untrusted tagged data.", "fixTitle": "What the fix changes", "fix": "Use safe_load, bound input size, and validate expected keys, types and ranges.", "action": "View proposed fix →", "finding": "Safe YAML deserialization needs attention", "instruction": "Use safe_load, bound input size, and validate expected keys, types and ranges.", "limit": "This rule detects selected unsafe YAML loaders only. safe_load does not authenticate the sender, prove data integrity or eliminate all resource risks.", "mode": "scan", "highlights": {"vulnerable": [6], "fixed": [6, 7, 8, 9, 10, 11, 12, 13, 14]}}, "logging": {"name": "Observable access denials", "category": "A09:2025 Security Logging and Alerting Failures", "source": "https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/", "file": "logging.py", "title": "Review: Observable access denials", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "Unrecorded access denials can hide repeated attempts to reach protected records.", "fixTitle": "What the fix changes", "fix": "Record structured security events without credentials, protect storage, and configure actionable alert routing with an accountable responder.", "action": "View proposed fix →", "finding": "Observable access denials needs attention", "instruction": "Record structured security events without credentials, protect storage, and configure actionable alert routing with an accountable responder.", "limit": "The lab records synthetic events and a threshold alert in memory, sending nothing externally. Real protected retention, redaction, alert delivery and human response still need integration tests.", "mode": "behavioral", "highlights": {"vulnerable": [4], "fixed": [5]}}, "errors": {"name": "Fail closed on timeout", "category": "A10:2025 Mishandling of Exceptional Conditions", "source": "https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/", "file": "errors.py", "title": "Review: Fail closed on timeout", "intro": "A pull request is a proposed code change. Compare this example, understand the risk, then inspect the fix.", "before": "Original · vulnerable example", "after": "Fixed · proposed improvement", "risk": "What could go wrong?", "impact": "Granting access when a policy service times out turns an outage into an authorization bypass.", "fixTitle": "What the fix changes", "fix": "Deny access on the illustrated timeout. The caller should expose a safe error and record the outage.", "action": "View proposed fix →", "finding": "Fail closed on timeout needs attention", "instruction": "Deny access on the illustrated timeout. The caller should expose a safe error and record the outage.", "limit": "The lab checks a healthy allow and denial on timeout. Real-service failures, cleanup, rollback, safe responses and bounded retries need separate validation.", "mode": "behavioral", "highlights": {"vulnerable": [6], "fixed": [8]}}};
function scenarioText(){const info=scenarios[scenario];$('scenario').value=scenario;$('scenario-title').textContent=info.title;$('category').textContent=info.category;$('category-source').href=info.source;$('review-mode').textContent=info.mode==='behavioral'?'Check method: real behavioral test using synthetic lab services. Semgrep is not applicable.':'Check method: live Semgrep scan of one narrow pattern. Behavioral execution is not applicable.';$('scenario-intro').textContent=info.intro;$('vulnerable').textContent=info.before;$('fixed').textContent=info.after;}
let fixtures, variant = 'vulnerable', diff = false, busy = false, runs = [], active = null;
const stageNames = ['load','scan','behavior','review'];
const labels = {review:'Review required',queued:'Queued',running:'Running',success:'Passed',failure:'Failed',error:'Error',skipped:'Not run',idle:'Not started'};
const symbols = {review:'◇',queued:'○',running:'◉',success:'✓',failure:'×',error:'!',skipped:'−',idle:'○'};
function source(line) {
  $('code').replaceChildren();
  const text = fixtures ? (diff ? fixtures.diff : fixtures.source[variant]) : 'Sample unavailable for this run.';
  let oldLine=0,newLine=0;
  text.trimEnd().split('\n').forEach((text, i) => {
    let markedVariant=variant, sourceLine=i+1;
    if(diff){
      const hunk=text.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      sourceLine=null;
      if(hunk){oldLine=Number(hunk[1]);newLine=Number(hunk[2]);}
      else if(!text.startsWith('---')&&!text.startsWith('+++')){
        if(text.startsWith('-')){markedVariant='vulnerable';sourceLine=oldLine++;}
        else if(text.startsWith('+')){markedVariant='fixed';sourceLine=newLine++;}
        else if(text.startsWith(' ')){oldLine++;newLine++;}
      }
    }
    const highlighted=sourceLine!==null&&(fixtures?.highlights?.[markedVariant]||[]).includes(sourceLine);
    const row = document.createElement('span');row.className = 'line';
    if (diff && text.startsWith('+')) row.classList.add('add');
    if (diff && text.startsWith('-')) row.classList.add('remove');
    if (!diff && i + 1 === line) row.classList.add('selected');
    const number = document.createElement('span');number.className = 'number';number.textContent = i + 1;
    row.append(number);
    if(highlighted){
      row.classList.add(markedVariant==='fixed'?'fix-line':'vulnerable-line');
      const cue=document.createElement('span');cue.className='line-cue';cue.textContent=markedVariant==='fixed'?'Fix':'Vulnerable';
      const basis=fixtures.review_mode==='manual'?'Illustrative review focus, not scanner evidence':'Illustrative code focus; actual scanner evidence appears in findings';
      cue.title=basis;cue.setAttribute('aria-label',cue.textContent+'. '+basis);row.append(cue);
    }
    row.append(document.createTextNode(text));$('code').append(row);
  });
  $('highlight-note').textContent=fixtures?.review_mode==='behavioral'?'Red / Vulnerable and green / Fix mark the lab’s relevant code. Behavioral results below test only the stated synthetic conditions, not production services.':'Red / Vulnerable and green / Fix mark the specific example lines. Actual Semgrep findings are shown separately. Unmarked lines and green lines are not proof of security.';
  $('filename').textContent = diff ? scenarios[scenario].file + ' · original → fixed' : scenarios[scenario].file + ' · ' + (variant === 'fixed' ? 'fixed' : 'original');
  $('diff').textContent = diff ? 'Show selected code' : 'Show fix diff';$('diff').setAttribute('aria-pressed',String(diff));
  $('selected').textContent = 'Selected: ' + (variant === 'fixed' ? 'fixed ' + scenarios[scenario].name + ' example' : 'original example');
  ['vulnerable','fixed'].forEach(id => {$(id).classList.toggle('active',variant === id);$(id).setAttribute('aria-pressed',String(variant === id));});
  $('explain-title').textContent = variant === 'fixed' ? scenarios[scenario].fixTitle : scenarios[scenario].risk;
  $('explain').textContent = variant === 'fixed' ? scenarios[scenario].fix : scenarios[scenario].impact;
  $('apply').textContent = variant === 'fixed' ? 'Return to original example' : scenarios[scenario].action;
}
function badge(status, text) {$('overall').className = 'badge '+status;$('overall').textContent = text;}
function paintStage(name,state) {
  const node = $('stage-'+name);node.className = 'job '+state;
  node.querySelector('.job-icon').textContent = symbols[state];node.querySelector('small').textContent = labels[state];
  $('log-'+name+'-state').textContent = labels[state];
}
function empty(title,message) {
  const div=document.createElement('div');div.className='empty';
  const h=document.createElement('h3');h.textContent=title;const p=document.createElement('p');p.textContent=message;
  div.append(h,p);$('findings').replaceChildren(div);
}
function reset() {
  active=null;badge('neutral','Not run');$('duration').textContent='No run for this selection';
  $('activity').textContent='This selection has no active result. Run the workflow to check it.';
  $('annotation-count').textContent='No result yet';
  stageNames.forEach(name=>{paintStage(name,'idle');$(name+'-log').textContent='No activity for this selection.';});
  empty('Ready for a new run','Choose “Run workflow” to check the selected version. A previous version’s result does not apply.');
  renderHistory();
}
function setBusy(value) {
  busy=value;['run','apply','vulnerable','fixed','diff','scenario'].forEach(id=>$(id).disabled=value);
  document.querySelectorAll('.history-run').forEach(button=>button.disabled=value);
  $('findings').setAttribute('aria-busy',String(value));$('run').textContent=value?'Workflow running…':'Run workflow';
}
function select(value) {if(busy)return;variant=value;diff=false;source();reset();}
function renderHistory() {
  $('history').replaceChildren();$('run-count').textContent=runs.length;
  if(!runs.length){const p=document.createElement('p');p.className='empty-history';p.textContent='Your runs will appear here.';$('history').append(p);return;}
  [...runs].reverse().forEach(run=>{
    const button=document.createElement('button');button.className='history-run'+(active===run?' active':'');button.disabled=busy;
    const title=document.createElement('strong');title.textContent=`${symbols[run.status]||'○'} #${run.id} ${scenarios[run.scenario].name} · ${run.variant==='fixed'?'Fixed':'Original'}`;
    const meta=document.createElement('small');meta.textContent=`${run.started} · ${run.status==='success'?'Checks passed':run.status==='failure'?'Checks failed':run.status==='error'?'Check error':labels[run.status]||run.status} · ${scenarios[run.scenario].mode==='behavioral'?'Behavioral tests':'Static analysis'}`;
    button.append(title,meta);button.onclick=()=>{if(busy)return;active=run;scenario=run.scenario;fixtures=run.fixtures;scenarioText();variant=run.variant;diff=false;source();renderRun(run);renderHistory();};$('history').append(button);
  });
}
function result(run) {
  $('findings').replaceChildren();
  if(run.status==='running'||run.status==='queued'){empty('Workflow in progress','The jobs above show what is happening. Open a job to see its observed activity.');return;}
  const data=run.data;
  if(run.status==='error'){
    $('annotation-count').textContent='No complete result';
    const div=document.createElement('div');div.className='annotation error';
    const title=document.createElement('h3');title.textContent='Check error';const p=document.createElement('p');p.textContent=run.message+' No passing result was issued. Retry the workflow after checking the local server.';
    div.append(title,p);$('findings').append(div);return;
  }
  const summary=document.createElement('div');summary.className='result-summary '+run.status;
  const heading=document.createElement('h3');heading.textContent=run.status==='success'?'Checks passed':'Checks failed';
  const metric=document.createElement('p');metric.className='result-method';metric.textContent=data.engine==='behavioral'?'Behavioral tests · '+data.assertions.filter(a=>a.passed).length+'/'+data.assertions.length+' assertions passed':'Static analysis · '+data.findings.length+' finding'+(data.findings.length===1?'':'s')+' for this rule';
  const scope=document.createElement('p');scope.textContent=scenarios[run.scenario].limit+' This result does not prove full production security.';
  summary.append(heading,metric,scope);$('findings').append(summary);
  if(data.engine==='behavioral'){
    const passed=data.assertions.filter(a=>a.passed).length;
    $('annotation-count').textContent=passed+'/'+data.assertions.length+' assertions passed';
    const article=document.createElement('article');article.className='annotation'+(run.status==='success'?' pass':'');
    const title=document.createElement('h3');title.textContent='Assertion evidence';
    const note=document.createElement('p');note.textContent='Harness completed successfully in '+data.elapsed_ms+' ms. A failed security assertion demonstrates the vulnerable behavior; it is not a broken test harness.';
    const list=document.createElement('ul');data.assertions.forEach(a=>{const item=document.createElement('li');item.textContent=(a.passed?'PASS: ':'FAIL: ')+a.name+' — '+a.evidence;list.append(item);});
    const scope=document.createElement('p');scope.textContent='Synthetic adapters only. No production services, dependencies, sessions or alerts were used.';
    article.append(title,note,list,scope);$('findings').append(article);return;
  }
  $('annotation-count').textContent=data.findings.length+' finding'+(data.findings.length===1?'':'s');
  if(!data.findings.length){const div=document.createElement('div');div.className='annotation pass';const label=document.createElement('span');label.className='label';label.textContent='✓ REAL LOCAL SCAN';const h=document.createElement('h3');h.textContent='Rule evidence';const p=document.createElement('p');p.textContent='The selected rule reported no findings in this fixture.';div.append(label,h,p);$('findings').append(div);return;}
  data.findings.forEach(f=>{
    const div=document.createElement('article');div.className='annotation';
    const label=document.createElement('span');label.className='label';label.textContent='× '+f.severity+' · REAL SEMGREP FINDING';
    const h=document.createElement('h3');h.textContent=scenarios[run.scenario].finding;
    const impact=document.createElement('p');impact.textContent=scenarios[run.scenario].impact;
    const fix=document.createElement('p');fix.textContent=scenarios[run.scenario].instruction;
    const button=document.createElement('button');button.textContent=`${scenarios[run.scenario].file} · line ${f.start_line} →`;button.onclick=()=>{variant=run.variant;diff=false;source(f.start_line);$('code').focus();};
    const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Technical evidence';const raw=document.createElement('pre');raw.textContent=JSON.stringify(f,null,2);details.append(summary,raw);
    div.append(label,h,impact,button,fix,details);$('findings').append(div);
  });
}
function renderRun(run) {
  const text={queued:'Queued',running:'Running',success:'Checks passed',failure:'Checks failed',error:'Check error'};
  badge(run.status,text[run.status]);$('duration').textContent=run.elapsed===null?'Run in progress':`Run #${run.id} · ${run.elapsed.toFixed(2)}s (local elapsed)`;
  stageNames.forEach(name=>{paintStage(name,run.stages[name]);$(name+'-log').textContent=run.logs[name].join('\n')||'Waiting for preceding job.';});
  $('activity').textContent=run.message;result(run);
}
function event(run,stage,state,message){run.stages[stage]=state;run.logs[stage].push(`[+${((performance.now()-run.start)/1000).toFixed(2)}s] ${message}`);run.message=message;renderRun(run);}
async function loadFixtures(){const r=await fetch('/api/fixtures/'+scenario);if(!r.ok)throw new Error('The bundled sample could not be loaded.');const data=await r.json();if(!data.source?.vulnerable||!data.source?.fixed)throw new Error('The sample response was incomplete.');fixtures=data;source();}
$('run').onclick=async()=>{
  if(busy)return;
  const run={id:runs.length+1,scenario,fixtures:null,variant,status:'queued',start:performance.now(),started:new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}),elapsed:null,stages:{load:'queued',scan:'queued',behavior:'queued',review:'queued'},logs:{load:[],scan:[],behavior:[],review:[]},data:null,message:'Local run requested.'};
  runs.push(run);active=run;setBusy(true);renderHistory();renderRun(run);let current='load';
  try{
    run.status='running';event(run,'load','running','Requesting the bundled sample from the local server.');
    await loadFixtures();run.fixtures=fixtures;
    const behavioral=scenarios[run.scenario].mode==='behavioral';
    event(run,'load','success',behavioral?'Authored fixture loaded. Only its pinned source may execute with synthetic lab adapters.':'Trusted fixture loaded for static scanning only; it will not execute.');
    event(run,behavioral?'scan':'behavior','skipped','Not applicable to this example.');
    current=behavioral?'behavior':'scan';event(run,current,'running',behavioral?'Running the bounded synthetic behavioral harness.':'Running real Semgrep against the selected trusted fixture.');
    const response=await fetch('/api/scan/'+run.scenario+'/'+run.variant,{method:'POST',headers:{'X-PRSEC-Demo':'1'}});const data=await response.json();
    if(!response.ok||data.status==='error')throw new Error('The local check did not return a complete result.');
    if(!['success','failure'].includes(data.status)||!Array.isArray(data.findings)||data.variant!==run.variant||data.scenario!==run.scenario||data.engine!==(behavioral?'behavioral':'semgrep'))throw new Error('The check response was incomplete or inconsistent.');
    if(behavioral&&(!data.harness_completed||!Array.isArray(data.assertions)||!data.assertions.length||data.assertions.some(a=>typeof a.passed!=='boolean')||data.status!==(data.assertions.every(a=>a.passed)?'success':'failure')))throw new Error('Behavioral assertion evidence was incomplete or inconsistent.');
    if(!behavioral&&data.status!==(data.findings.length?'failure':'success'))throw new Error('Scanner verdict did not match its findings.');
    run.data=data;
    event(run,current,behavioral?data.status:'success',behavioral?'Harness completed; '+data.assertions.filter(a=>a.passed).length+'/'+data.assertions.length+' security assertions passed in '+data.elapsed_ms+' ms.':'Scanner completed; received '+data.findings.length+' finding(s).');
    current='review';run.status=data.status;event(run,'review',run.status,behavioral?'Results are actual synthetic fixture behavior, not proof of production/category coverage.':data.findings.length?'A vulnerable pattern was found. Inspect the fix and rerun.':'No findings for this rule. Broader security remains outside this test.');
  }catch(error){run.status='error';run.message=error.message;event(run,current,'error',error.message);stageNames.forEach(name=>{if(run.stages[name]==='queued')run.stages[name]='skipped';});}
  finally{run.elapsed=(performance.now()-run.start)/1000;setBusy(false);renderRun(run);renderHistory();}
};
['vulnerable','fixed'].forEach(id=>$(id).onclick=()=>select(id));
$('apply').onclick=()=>{select(variant==='fixed'?'vulnerable':'fixed');$('run').focus();};
$('diff').onclick=()=>{if(busy)return;diff=!diff;source();};
document.querySelectorAll('[data-log]').forEach(button=>button.onclick=()=>{const detail=$('log-'+button.dataset.log);detail.open=true;detail.scrollIntoView({block:'nearest',behavior:'smooth'});detail.querySelector('summary').focus();});
$('scenario').onchange=async()=>{scenario=$('scenario').value;variant='vulnerable';diff=false;fixtures=null;scenarioText();reset();$('code').textContent='Loading selected sample…';setBusy(true);try{await loadFixtures();}catch(_){$('code').textContent='Sample unavailable. Check the local server, then choose Run workflow to retry.';badge('error','Sample unavailable');$('activity').textContent='The sample could not load. Retry the workflow.';}finally{setBusy(false);}};
scenarioText();setBusy(true);loadFixtures().catch(()=>{$('code').textContent='Sample unavailable. Check the local server, then choose Run workflow to retry.';badge('error','Sample unavailable');$('activity').textContent='The sample could not load. Start the local server and retry “Run workflow”.';}).finally(()=>setBusy(false));
