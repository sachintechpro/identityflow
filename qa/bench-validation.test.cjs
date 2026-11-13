'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const htmlPath=process.env.QA_BENCH_PATH;
const indexPath=process.env.QA_INDEX_PATH;
if(!htmlPath||!indexPath)throw Error('QA_BENCH_PATH and QA_INDEX_PATH must be specified');
const read=p=>fs.readFileSync(path.resolve(process.cwd(),p),'utf8');
const html=read(htmlPath),index=read(indexPath);
const match=html.match(/<script id="qa-config" type="application\/json">([\s\S]*?)<\/script>/);
assert.ok(match,'Expected standalone JSON config');
const app=JSON.parse(match[1]);
const uniq=a=>new Set(a).size===a.length;
test('QA route linked from existing application without altering its business logic',()=>{
  assert.ok(index.includes('qa-bench.html'),'App must link its QA page');
  assert.ok(html.includes('id="app"')&&html.includes('data-tab="automation"'));
  assert.match(html,/<meta name="viewport"/);
});
test('Requirements are detailed, distinct and risk-classified',()=>{
  assert.ok(app.requirements.length>=4);
  assert.ok(uniq(app.requirements.map(r=>r.id)));
  for(const r of app.requirements){
    assert.ok(r.title.length>8&&r.acceptance.length>35&&r.clarify.length>30,r.id);
    assert.ok(['P0','P1','P2'].includes(r.risk),r.id);
  }
});
test('Manual cases have steps, expected behavior and requirement traceability',()=>{
  const valid=new Set(app.requirements.map(r=>r.id));
  assert.ok(app.cases.length>=5);
  assert.ok(uniq(app.cases.map(x=>x.id)));
  for(const c of app.cases){
    assert.ok(valid.has(c.req),c.id);
    for(const k of ['title','pre','steps','expected','level'])assert.ok(c[k]&&String(c[k]).length>5,c.id+' '+k);
    assert.ok(['P0','P1','P2'].includes(c.priority),c.id+' priority');
    assert.ok(c.steps.split('\n').length>=4,c.id);
  }
});
test('Automation definitions are safe read-only checks, not static pass counters',()=>{
  assert.ok(app.automatic.length>=4);
  assert.ok(uniq(app.automatic.map(x=>x.id)));
  for(const c of app.automatic){
    assert.ok(c.title&&c.level,c.id);
    if(c.kind==='http'){assert.ok(c.path.startsWith('/'),c.id);assert.ok(Number.isInteger(c.expectStatus),c.id);}
    else if(c.kind==='esm'){assert.ok(c.module==='./engine.mjs'&&['simulate','evaluate'].includes(c.fn),c.id);}
    else assert.fail('Unsupported check kind '+c.id);
  }
  assert.ok(html.includes('fetch(path,{method:\'GET\''),'HTTP checks should explicitly be GET');
  assert.ok(html.includes('Not run'),'Results must be unexecuted until run');
});
test('Manual results, defects, evidence and exports are functionally present',()=>{
  for(const s of ['manual-form','defect-form','evidence-upload','storeFile','openFile','export-json','export-csv','localStorage','indexedDB'])assert.ok(html.includes(s),s);
  assert.ok(html.includes('tester-entered'));
});
test('QA Bench JavaScript is syntactically valid',()=>{
  const source=process.env.QA_BENCH_SCRIPT ? read(process.env.QA_BENCH_SCRIPT) : html.match(/<script>([\s\S]*?)<\/script><\/body><\/html>/)?.[1];
  assert.ok(source,'Script must exist');
  new vm.Script(source,{filename:'qa-bench.js'});
});
