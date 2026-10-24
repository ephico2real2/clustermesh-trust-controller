import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const base=process.env.CMTC_GRAFANA_URL || 'http://127.0.0.1:3000';
const requireNative=process.env.CMTC_REQUIRE_NATIVE_MTLS==='true';
const to=Number(process.env.CMTC_CAPTURE_TO_MS || Date.now());
const from=Number(process.env.CMTC_CAPTURE_FROM_MS || to-15*60*1000);
if(!Number.isSafeInteger(from)||!Number.isSafeInteger(to)||to<=from)throw Error('Invalid absolute capture range');
const output=process.env.S || path.resolve('artifacts/screenshots');
await mkdir(output,{recursive:true});
const headers={Authorization:`Basic ${Buffer.from('admin:cmtc-disposable-lab').toString('base64')}`};
async function api(route){const r=await fetch(base+route,{headers});if(!r.ok)throw Error(`${route}: HTTP ${r.status}`);return r.json();}
let metricsError;
for(let i=0;i<60;i++){
  try{
    const data={};
    for(const [name,query] of Object.entries({selected:'sum by (cluster) (cmtc_namespaces_selected{component="cmtc-controller"})',agents:'sum by (cluster) (cmtc_node_agent_ready{component="cmtc-node-agent"})',enforcement:'max by (cluster) (cmtc_enforcement_available{component="cmtc-controller"})'})){
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
const found=await api('/api/search?type=dash-db');
const dashboards=found.filter(d=>['cmtc-observe-lab','cmtc-authenticated-only'].includes(d.uid));
if(dashboards.length!==2)throw Error('Expected Operations and Workload Security with all nine original domains consolidated');
const spec={viewport:{width:1920,height:4800},pages:[]};
const index=[];
for(const d of dashboards){
  const detail=await api(`/api/dashboards/uid/${encodeURIComponent(d.uid)}`);
  const panels=detail.dashboard.panels.filter(p=>p.type!=='row');
  for(const theme of ['dark','light']){
    const name=`${d.uid==='cmtc-observe-lab'?'cmtc-operations':'cmtc-workload-security'}-${theme}`;
    // Planned panels must remain visible. Their missing signals are explicit
    // blockers, not failed browser rendering or invented successful zeros.
    const allowed=panels.filter(p=>p.title.endsWith('· planned') || (!requireNative && d.uid==='cmtc-authenticated-only' && p.targets?.length)).map(p=>p.title);
    spec.pages.push({name,url:base+d.url+`?kiosk&theme=${theme}&from=${from}&to=${to}`,evidence:'panels',fullPage:true,before:2500,blockedSignalsOnNoData:true,expect:{panelsMin:panels.length,noDataAllowed:allowed},unavailableReasons:Object.fromEntries(allowed.map(title=>[title,title.endsWith('· planned')?'Planned instrumentation; implement and qualify in its assigned agile story.':'Native security signal requires the separate SPIRE fixture, outside baseline Observe CI.']))});
    index.push({title:`${d.title} (${theme})`,file:`${name}.png`,uid:d.uid});
  }
}
spec.pages.push({name:'application-global-service',url:'http://127.0.0.1:18080',evidence:'text',settle:false,before:500,expect:{text:['poc2']}});
index.push({title:'Imported Global Service backend',file:'application-global-service.png'});
const specPath=path.join(output,'walk-spec.json');
await writeFile(specPath,JSON.stringify(spec,null,2)+'\n');
await writeFile(path.join(output,'capture-range.json'),JSON.stringify({fromMilliseconds:from,toMilliseconds:to,requireNative},null,2)+'\n');
await writeFile(path.join(output,'index.json'),JSON.stringify(index,null,2)+'\n');
const walked=spawnSync(process.execPath,[fileURLToPath(new URL('./walk.cjs',import.meta.url)),specPath],{env:{...process.env,S:output},stdio:'inherit'});
if(metricsError){console.error(metricsError.message);process.exitCode=1;}
else process.exitCode=walked.status ?? 1;
