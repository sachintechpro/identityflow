'use strict';
/** Verify traceable technical QA catalog entries are backed by real source. */
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=process.cwd();
const read=p=>fs.readFileSync(path.resolve(root,p),'utf8');
const htmlPath=process.env.QA_BENCH_PATH, indexPath=process.env.QA_INDEX_PATH;
assert.ok(htmlPath&&indexPath,'QA_BENCH_PATH and QA_INDEX_PATH required');
const html=read(htmlPath),index=read(indexPath);
const m=html.match(/<script id="qa-config" type="application\/json">([\s\S]*?)<\/script>/);
assert.ok(m,'QA config JSON');
const config=JSON.parse(m[1]),js=process.env.QA_BENCH_SCRIPT?read(process.env.QA_BENCH_SCRIPT):html.match(/<script>([\s\S]*?)<\/script><\/body><\/html>/)?.[1];
const cats=new Set(['Unit / business rules','Functional / regression','API / contract','SIT / integration','E2E / workflow','UX / responsive','Security / RBAC','UAT / smoke']);
test('All six original QA lifecycle sections remain present and interactive',()=>{
  for(const tab of ['requirements','cases','manual','automation','defects','report']){
    assert.ok(html.includes('data-tab="'+tab+'"'),'Original tab absent: '+tab);
  }
  for(const form of ['manual-form','custom-form','defect-form','evidence-upload','export-json','export-csv','run-all','run-one','reset-auto']){
    assert.ok(js.includes(form),'Existing feature missing: '+form);
  }
  assert.ok(index.includes('qa-bench.html'),'Main application links its QA Bench');
});
test('Four new engineering sections have runnable, wired controls',()=>{
  for(const tab of ['engineering','catalog','ci','gates'])assert.ok(html.includes('data-tab="'+tab+'"'),'Engineering tab missing '+tab);
  for(const fn of ['qaEngineering','qaCatalog','qaCiView','qaQualityGates','qaRefreshCi']){
    assert.ok(js.includes('function '+fn+'('),'New view missing '+fn);
  }
  for(const act of ['qa-go-runner','qa-open-category','qa-refresh-ci','qa-tech-category','qa-go-catalog']){
    assert.ok(js.includes(act),'Interactive control missing '+act);
  }
  assert.ok(js.includes('api.github.com/repos/'),'Actual public GitHub Actions endpoint missing');
  assert.ok(js.includes("request")&&js.includes("actual"),'Existing technical proof fields missing');
});
test('Source-backed technical test catalog has distinct IDs and real source files',()=>{
  assert.ok(Array.isArray(config.technicalCases)&&config.technicalCases.length>=5);
  assert.equal(new Set(config.technicalCases.map(t=>t.id)).size,config.technicalCases.length);
  for(const entry of config.technicalCases){
    assert.ok(cats.has(entry.category),'Unrecognized category '+entry.category);
    assert.ok(/^[\w./-]+$/.test(entry.file),'Unexpected source path '+entry.file);
    assert.ok(fs.existsSync(path.join(root,entry.file)),'Source file missing '+entry.file);
    assert.ok(Number.isInteger(entry.line)&&entry.line>0,'Missing source line '+entry.id);
    assert.ok(entry.excerpt?.length>=6,'Missing source excerpt '+entry.id);
    const content=read(entry.file).split('\n');
    assert.ok(entry.line<=content.length,'Line out of range '+entry.id);
    const nearby=content.slice(entry.line-1,Math.min(content.length,entry.line+18)).join('\n');
    const leading=entry.excerpt.slice(0,Math.min(entry.excerpt.length,35));
    assert.ok(nearby.includes(leading),'Unmatched source assertion '+entry.file+' line '+entry.line+' excerpt '+leading);
  }
});
test('QA workbench lists source suites and verifiable CI workflows',()=>{
  assert.ok(config.suites.length>=1);
  assert.ok(config.workflows.length>=1);
  for(const suite of config.suites)assert.ok(fs.existsSync(path.join(root,suite.file)),'Suite source missing '+suite.file);
  for(const workflow of config.workflows)assert.ok(fs.existsSync(path.join(root,workflow.path)),'Workflow source missing '+workflow.path);
});
test('No synthetic pass rates or auto-filled CI status are used',()=>{
  assert.ok(js.includes('qaCiRuns=null'),'CI unknown until read from actual API');
  assert.ok(js.includes('qaCiBusy'),'CI fetch progress is tracked');
  assert.ok(js.includes('No verified workflow runs loaded'),'CI unknown state disclosed');
  assert.ok(js.includes('No execution verdict has been claimed'),'Manual not-run evidence preserved');
});
