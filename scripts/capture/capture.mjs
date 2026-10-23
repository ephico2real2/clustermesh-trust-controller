import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const base='http://127.0.0.1:3000';
const output=process.env.S || path.resolve('artifacts/screenshots');
await mkdir(output,{recursive:true});
const headers={Authorization:`Basic ${Buffer.from('admin:cmtc-disposable-lab').toString('base64')}`};
async function api(route){const r=await fetch(base+route,{headers});if(!r.ok)throw Error(`${route}: HTTP ${r.status}`);return r.json();}
let metricsError;
for(let i=0;i<60;i++){
  try{
    const data={};
    for(const [name,query] of Object.entries({selected:'sum by (cluster) (cmtc_namespaces_selected)',agents:'sum by (cluster) (cmtc_node_agent_ready)',enforcement:'max by (cluster) (cmtc_enforcement_available)'})){
      const result=await api(`/api/datasources/proxy/uid/cmtc-prom/api/v1/query?query=${encodeURIComponent(query)}`);
      if(result.status!=='success')throw Error(`Prometheus rejected ${name}`);
      data[name]=Object.fromEntries(result.data.result.map(s=>[s.metric.cluster,Number(s.value[1])]));
    }
    for(const cluster of ['cmtc-a','cmtc-b']){
      if(!(data.selected[cluster]>=2)||data.agents[cluster]!==2||data.enforcement[cluster]!==0)throw Error(`Incomplete or misleading telemetry for ${cluster}: ${JSON.stringify(data)}`);
    }
    await writeFile(path.join(output,'metric-assertions.json'),JSON.stringify(data,null,2)+'\n');
    metricsError=undefined;break;
  }catch(e){metricsError=e;await new Promise(r=>setTimeout(r,2000));}
}
const dashboards=await api('/api/search?type=dash-db');
if(dashboards.length!==10)throw Error(`Expected nine domain dashboards and one live evaluation dashboard, got ${dashboards.length}`);
const available=new Set(['cmtc_namespace_decisions','cmtc_namespaces_eligible','cmtc_namespaces_selected','cmtc_namespaces_enrolled','cmtc_enforcement_available','cmtc_policy_evaluations_total','cmtc_node_agent_ready','cmtc_pods_observed']);
const spec={viewport:{width:1600,height:1100},pages:[]};
const index=[];
for(const d of dashboards.sort((a,b)=>a.uid.localeCompare(b.uid))){
  const detail=await api(`/api/dashboards/uid/${encodeURIComponent(d.uid)}`);
  const panels=detail.dashboard.panels.filter(p=>p.type!=='row');
  const noDataReasons={};
  for(const p of panels){
    const metrics=(p.targets||[]).flatMap(t=>(t.expr||'').match(/\bcmtc_[a-zA-Z0-9_]+/g)||[]);
    const missing=metrics.filter(m=>!available.has(m));
    if(missing.length)noDataReasons[p.title]=`Not implemented in Observe: ${[...new Set(missing)].join(', ')}`;
  }
  spec.pages.push({name:d.uid,url:base+d.url+'?kiosk&from=now-15m&to=now',evidence:'panels',fullPage:true,before:2500,expect:{panelsMin:panels.length,noDataAllowed:Object.keys(noDataReasons)},blockedSignalsOnNoData:true,noDataReasons});
  index.push({title:d.title,file:`${d.uid}.png`,uid:d.uid});
}
spec.pages.push({name:'application-global-service',url:'http://127.0.0.1:18080',evidence:'text',settle:false,before:500,expect:{text:['poc2']}});
index.push({title:'Imported Global Service backend',file:'application-global-service.png'});
const specPath=path.join(output,'walk-spec.json');
await writeFile(specPath,JSON.stringify(spec,null,2)+'\n');
await writeFile(path.join(output,'index.json'),JSON.stringify(index,null,2)+'\n');
const walked=spawnSync(process.execPath,[fileURLToPath(new URL('./walk.cjs',import.meta.url)),specPath],{env:{...process.env,S:output},stdio:'inherit'});
if(metricsError){console.error(metricsError.message);process.exitCode=1;}
else process.exitCode=walked.status ?? 1;
