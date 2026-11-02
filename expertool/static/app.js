'use strict';
const $ = (id) => document.getElementById(id);
let snapshot = null, tab = 'findings', state = 'all', token = '', selectedFinding = null, generation = 0;
function node(tag, text, className) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; }
function badge(value) { return node('span', value, 'badge ' + value); }
async function api(url, options) { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw new Error(data.error || 'Request failed'); return data; }
function notify(message = '') { $('notice').textContent = message; }
function render() {
  const exists = Boolean(snapshot);
  $('empty-workspace').hidden = exists;
  $('workspace-panel').hidden = !exists || tab === 'scope';
  $('scope-panel').hidden = !exists || tab !== 'scope';
  $('export').hidden = !exists;
  $('view-title').textContent = {findings:'Findings', assets:'Asset inventory', scope:'Program scope', runs:'Runs & schedules'}[tab];
  $('subtitle').textContent = {findings:'Review the evidence. Decide what matters.', assets:'Discovered hosts and observed HTTP endpoints.', scope:'The boundaries of your assessment.', runs:'Execution history and persistent recurring assessments.'}[tab];
  $('program-name').textContent = snapshot ? snapshot.program : 'Select a program';
  const findings = snapshot ? snapshot.findings : [];
  $('asset-count').textContent = snapshot ? snapshot.assets.length : '0';
  for (const status of ['candidate','confirmed','dismissed']) $(status + '-count').textContent = findings.filter(f=>f.state === status).length;
  if (!exists) return;
  $('export').href = '/api/report?program=' + encodeURIComponent(snapshot.program);
  document.querySelector('.tabs').hidden = tab !== 'findings';
  $('severity').hidden = tab !== 'findings';
  if (tab === 'scope') {
    $('scan-policy').textContent=JSON.stringify({scan:snapshot.policy.scan || {note:'Default budgets apply'},automation:snapshot.policy.automation || {note:'Legacy policy; active mode must still be explicitly permitted'},scope_review:snapshot.policy.scope_review || null},null,2);
    for (const [id,key] of [['included','include'],['excluded','exclude'],['allowed','allowed_modes']]) {
      $(id).replaceChildren(...((key === 'allowed_modes' ? snapshot.policy : snapshot.policy.asset_scope || snapshot.policy)[key] || (key === 'allowed_modes' ? ['passive','manual'] : [])).map(x=>node('li',x)));
      if (!$(id).children.length) $(id).append(node('li','None'));
    }
    return;
  }
  if (tab === 'runs') {
    const region=node('div');
    region.className='scope-panel';
    region.append(node('h2','Assessment runs'));
    if(!snapshot.runs.length)region.append(node('p','No runs yet. Start an assessment with the scan command.'));
    for(const run of snapshot.runs) {
      const item=node('details'), summary=node('summary',`#${run.id} · ${run.kind} · ${run.status} · ${run.started}`);
      item.append(summary,node('pre',JSON.stringify({config:run.config,result:run.result},null,2)));region.append(item);
    }
    const manualEvents=(snapshot.egress || []).filter(event=>event.tool==='intercept');
    if(manualEvents.length) {
      region.append(node('h2','Manual interception audit'));
      region.append(node('p','Request bodies and credentials are not stored. Injected researcher headers are marked below.'));
      for(const event of manualEvents.slice(0,100)) {
        const item=node('details');
        item.append(node('summary',`${event.created} · ${event.method || 'connection'} · ${event.host || 'unknown host'} · ${event.decision} · ${event.reason}`));
        item.append(node('pre',JSON.stringify({path_hash:event.path_hash,injected_researcher_headers:event.injected_headers || '[]',run_id:event.run_id},null,2)));
        region.append(item);
      }
    }
    region.append(node('h2','Schedules'));
    if(!snapshot.schedules.length)region.append(node('p','No schedules yet. Use schedule-add and start the worker from the CLI.'));
    for(const schedule of snapshot.schedules)region.append(node('pre',JSON.stringify({id:schedule.id,enabled:Boolean(schedule.enabled),interval_seconds:schedule.interval_seconds,seeds:schedule.seeds,next_due:new Date(schedule.next_due*1000).toISOString(),last_status:schedule.last_status},null,2)));
    $('table-region').replaceChildren(region);$('result-count').textContent=`${snapshot.runs.length} runs · ${snapshot.schedules.length} schedules`;return;
  }
  const query = $('search').value.toLowerCase(), severity = $('severity').value;
  let rows = tab === 'findings' ? findings.filter(f=>(state === 'all' || f.state === state) && (severity === 'all' || f.severity === severity)) : snapshot.assets;
  rows = rows.filter(row=>JSON.stringify(row).toLowerCase().includes(query));
  const table = node('table'), head = node('tr');
  const labels = tab === 'findings' ? ['SEVERITY','FINDING / ASSET','STATE','REVIEW'] : ['TYPE','ASSET','SOURCE','OBSERVATIONS'];
  for (const label of labels) { const th=node('th',label); th.scope='col'; head.append(th); }
  const thead=node('thead');thead.append(head);table.append(thead);const body=node('tbody');
  for (const row of rows) {
    const tr=node('tr');
    if (tab === 'findings') {
      const sev=node('td');sev.append(badge(row.severity));const title=node('td',undefined,'title');
      const link=node('button',row.title,'finding-link');link.addEventListener('click',()=>openFinding(row.id));
      title.append(link,node('span',row.url,'subtext'));const status=node('td');status.append(badge(row.state));
      const action=node('td'),button=node('button','Review →','button');button.addEventListener('click',()=>openFinding(row.id));action.append(button);tr.append(sev,title,status,action);
    } else {
      const type=node('td');type.append(badge(row.url.startsWith('dns://') ? 'dns' : 'http'));
      const asset=node('td',row.url,'mono'), source=node('td',row.source);
      const observations=snapshot.observations.filter(o=>o.asset === row.id), detail=node('td');
      const disclosure=node('details'),summary=node('summary',`${observations.length} observations`);disclosure.append(summary);
      for(const observation of observations) disclosure.append(node('pre',JSON.stringify({source:observation.source,metadata:observation.metadata},null,2)));
      detail.append(disclosure);tr.append(type,asset,source,detail);
    }
    body.append(tr);
  }
  table.append(body);
  $('table-region').replaceChildren(rows.length ? table : node('div', 'No matching records. Import saved output or adjust the filters.', 'empty'));
  $('result-count').textContent = `${rows.length} ${tab === 'findings' ? 'findings' : 'assets'} shown`;
}
function openFinding(id) {
  selectedFinding=snapshot.findings.find(f=>f.id===id);
  if (!selectedFinding) return;
  $('detail-title').textContent=selectedFinding.title;$('detail-url').textContent=selectedFinding.url;
  $('detail-badges').replaceChildren(badge(selectedFinding.severity),badge(selectedFinding.state));
  $('detail-validation').textContent=JSON.stringify((snapshot.validations || []).filter(v=>v.finding===id),null,2);
  $('detail-evidence').textContent=selectedFinding.evidence;$('review-status').textContent='';
  $('detail').showModal();
}
async function loadProgram() {
  const ticket=++generation, program=$('program').value;
  snapshot=null;render();
  if (!program) return;
  try { const data=await api('/api/snapshot?program='+encodeURIComponent(program)); if(ticket!==generation)return;snapshot=data;notify();render(); }
  catch(error) { if(ticket===generation)notify(error.message); }
}
async function refresh() {
  try {
    const previous=$('program').value, programs=await api('/api/programs');
    $('program').replaceChildren(...programs.map(p=>{const option=node('option',`${p.name} · ${p.candidates} to review`);option.value=p.name;return option;}));
    if(programs.some(p=>p.name===previous))$('program').value=previous;
    if(!programs.length){const option=node('option','No programs yet');option.value='';$('program').append(option);}
    await loadProgram();
  } catch(error) { notify(error.message); }
}
$('program').addEventListener('change',()=>{ $('detail').close();loadProgram(); });
$('refresh').addEventListener('click',refresh);
$('close-detail').addEventListener('click',()=>$('detail').close());
$('search').addEventListener('input',render);$('severity').addEventListener('change',render);
document.querySelectorAll('[data-tab]').forEach(button=>button.addEventListener('click',()=>{tab=button.dataset.tab;$('search').value='';document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b===button));render();}));
document.querySelectorAll('[data-state]').forEach(button=>button.addEventListener('click',()=>{state=button.dataset.state;document.querySelectorAll('[data-state]').forEach(b=>b.classList.toggle('active',b===button));render();}));
document.querySelectorAll('[data-review]').forEach(button=>button.addEventListener('click',async()=>{
  const finding=selectedFinding, program=snapshot.program;
  document.querySelectorAll('[data-review]').forEach(b=>b.disabled=true);
  try {
    await api('/api/review',{method:'POST',headers:{'Content-Type':'application/json','X-Expertool-Token':token},body:JSON.stringify({program,id:finding.id,state:button.dataset.review})});
    await refresh();
    if(snapshot && snapshot.program===program) {
      selectedFinding=snapshot.findings.find(f=>f.id===finding.id);
      $('detail-badges').replaceChildren(badge(selectedFinding.severity),badge(selectedFinding.state));
      $('review-status').textContent='Saved: '+selectedFinding.state;
    }
  } catch(error) {$('review-status').textContent=error.message;}
  finally {document.querySelectorAll('[data-review]').forEach(b=>b.disabled=false);}
}));
(async()=>{try {token=(await api('/api/session')).token;await refresh();}catch(error){notify(error.message);}})();
