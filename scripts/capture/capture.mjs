import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import dashboardSpec from './dashboard-spec.cjs';

const base=process.env.CMTC_GRAFANA_URL || 'http://127.0.0.1:3000';
const requireObserver=process.env.CMTC_REQUIRE_OBSERVER==='true';
const requireFence=process.env.CMTC_REQUIRE_FENCE==='true';
const requireNative=process.env.CMTC_REQUIRE_NATIVE_MTLS==='true';
const requireIssuer=process.env.CMTC_REQUIRE_ISSUER_PROFILE==='true';
const to=Number(process.env.CMTC_CAPTURE_TO_MS || Date.now());
const from=Number(process.env.CMTC_CAPTURE_FROM_MS || to-15*60*1000);
if(!Number.isSafeInteger(from)||!Number.isSafeInteger(to)||to<=from)throw Error('Invalid absolute capture range');
const output=process.env.S || path.resolve('artifacts/screenshots');
await mkdir(output,{recursive:true});
const headers={Authorization:`Basic ${Buffer.from('admin:cmtc-disposable-lab').toString('base64')}`};
const deadline=Number(process.env.CMTC_CAPTURE_DEADLINE_MS || Date.now()+10*60*1000);
if(!Number.isSafeInteger(deadline)||deadline<=Date.now())throw Error('Capture deadline expired');
const queryEvidence=[];
const allQueryEvidence=[];
async function api(route,name){
  const remaining=deadline-Date.now();
  if(remaining<=0)throw Error('Capture deadline expired');
  const at=new Date().toISOString();
  const r=await fetch(base+route,{headers,signal:AbortSignal.timeout(Math.min(5000,remaining))});
  if(!r.ok)throw Error(`${route}: HTTP ${r.status}`);
  const data=await r.json();
  if(route.includes('/api/v1/query?')){const row={name,requestedAt:at,query:new URL(base+route).searchParams.get('query'),response:data};queryEvidence.push(row);allQueryEvidence.push(row);}
  return data;
}
let metricsError;
for(let i=0;i<60 && Date.now()<deadline;i++){
  queryEvidence.length=0;
  try{
    const data={};
    for(const [name,query] of Object.entries({selected:'sum by (cluster) (cmtc_namespaces_selected{component="cmtc-controller"})',agents:'sum by (cluster) (cmtc_node_agent_ready{component="cmtc-node-agent"})',enforcement:'max by (cluster) (cmtc_enforcement_available{component="cmtc-controller"})'})){
      const result=await api(`/api/datasources/proxy/uid/cmtc-prom/api/v1/query?query=${encodeURIComponent(query)}&time=${to/1000}`,name);
      if(result.status!=='success')throw Error(`Prometheus rejected ${name}`);
      data[name]=Object.fromEntries(result.data.result.map(s=>[s.metric.cluster,Number(s.value[1])]));
    }
    for(const cluster of ['cmtc-a','cmtc-b']){
      if(!(data.selected[cluster]>=2)||data.agents[cluster]!==2||data.enforcement[cluster]!==0)throw Error(`Incomplete or misleading telemetry for ${cluster}: ${JSON.stringify(data)}`);
    }
    if(requireFence){
      for(const [name,query] of Object.entries({fenceVerified:'count by(cluster) (cmtc_datapath_fence_quarantine_verified{job="cmtc",component="cmtc-bpf-fence"} == 1)',fenceTargets:'count by(cluster) (up{job="cmtc",component="cmtc-bpf-fence"} == 1)'})){
        const result=await api(`/api/datasources/proxy/uid/cmtc-prom/api/v1/query?query=${encodeURIComponent(query)}&time=${to/1000}`,name);
        if(result.status!=='success'||result.warnings?.length||result.infos?.length)throw Error(`Fence query failed ${name}`);
        data[name]=Object.fromEntries(result.data.result.map(s=>[s.metric.cluster,Number(s.value[1])]));
        for(const cluster of ['cmtc-a','cmtc-b'])if(data[name][cluster]!==2)throw Error(`Missing four-node fence telemetry: ${JSON.stringify(data)}`);
      }
    }
    if(requireObserver){
      for(const [name,query] of Object.entries({observerVerified:'count by(cluster) (cmtc_datapath_observer_ready{job="cmtc",component="cmtc-bpf-observer"} == 1)',observerTargets:'count by(cluster) (up{job="cmtc",component="cmtc-bpf-observer"} == 1)'})){
        const result=await api(`/api/datasources/proxy/uid/cmtc-prom/api/v1/query?query=${encodeURIComponent(query)}&time=${to/1000}`,name);
        if(result.status!=='success'||result.warnings?.length||result.infos?.length)throw Error(`Observer query failed ${name}`);
        data[name]=Object.fromEntries(result.data.result.map(s=>[s.metric.cluster,Number(s.value[1])]));
        for(const cluster of ['cmtc-a','cmtc-b'])if(data[name][cluster]!==1)throw Error(`Missing two-worker observer telemetry: ${JSON.stringify(data)}`);
      }
    }
    if(requireIssuer){
      for(const [name,query] of Object.entries({issuerSourceAge:'time() - max by(cluster) (cmtc_issuer_profile_source_checked_timestamp_seconds{job="cmtc",component="cmtc-controller"} > 0)',issuerLeaseRemaining:'max by(cluster) (cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds{job="cmtc",component="cmtc-controller"} > 0) - time()'})){
        const result=await api(`/api/datasources/proxy/uid/cmtc-prom/api/v1/query?query=${encodeURIComponent(query)}&time=${to/1000}`,name);
        if(result.status!=='success'||result.warnings?.length||result.infos?.length)throw Error(`Issuer query failed ${name}`);
        data[name]=Object.fromEntries(result.data.result.map(s=>[s.metric.cluster,Number(s.value[1])]));
        for(const cluster of ['cmtc-a','cmtc-b']){
          const value=data[name][cluster];
          if(!Number.isFinite(value)||(name==='issuerSourceAge'?(value<0||value>120):(value<=0||value>30)))throw Error(`Issuer source/lease unavailable: ${JSON.stringify(data)}`);
        }
      }
    }
    await writeFile(path.join(output,'metric-assertions.json'),JSON.stringify(data,null,2)+'\n');
    metricsError=undefined;break;
  }catch(e){metricsError=e;await new Promise(r=>setTimeout(r,Math.min(2000,Math.max(0,deadline-Date.now()))));}
}
await writeFile(path.join(output,'metric-queries.json'),JSON.stringify({observedAt:new Date().toISOString(),queryTimeSeconds:to/1000,queries:queryEvidence,attempts:allQueryEvidence},null,2)+'\n');
const found=await api('/api/search?type=dash-db');
const dashboards=found.filter(d=>['cmtc-observe-lab','cmtc-authenticated-only'].includes(d.uid));
if(dashboards.length!==2)throw Error('Expected Operations and Workload Security with all nine original domains consolidated');
const spec={viewport:{width:1920,height:1200},pages:[]};
const index=[];
for(const d of dashboards){
  const detail=await api(`/api/dashboards/uid/${encodeURIComponent(d.uid)}`);
  const plan=dashboardSpec.capturePlan(detail.dashboard,{requireNative,requireFence,requireObserver});
  const panels=plan.panels;
  for(const theme of ['dark','light']){
    const name=`${d.uid==='cmtc-observe-lab'?'cmtc-operations':'cmtc-workload-security'}-${theme}`;
    // Planned capability panels remain in source and blocked evidence. Their
    // compact presentation must not turn unqualified security into a pass.
    const reasons=Object.fromEntries(panels.map(p=>[p.title,dashboardSpec.emptyReason(p,d.uid,{requireNative,requireFence,requireObserver,requireIssuer})]).filter(([,reason])=>reason));
    spec.pages.push({name,actions:plan.actions,blockedCapabilities:plan.blockedCapabilities,url:base+d.url+`?kiosk&theme=${theme}&from=${from}&to=${to}`,evidence:'panels',grafanaFullPage:true,fullPage:true,before:2500,blockedSignalsOnNoData:true,expect:{panelsMin:panels.length,panelTitles:panels.map(p=>p.title),noDataAllowed:Object.keys(reasons)},unavailableReasons:reasons});
    index.push({title:`${d.title} (${theme})`,file:`${name}.png`,uid:d.uid});
  }
}
spec.pages.push({name:'application-global-service',url:process.env.CMTC_APP_URL || 'http://127.0.0.1:28080',evidence:'text',settle:false,before:500,screenshot:false,expect:{text:['cmtc-b']}});
const specPath=path.join(output,'walk-spec.json');
await writeFile(specPath,JSON.stringify(spec,null,2)+'\n');
await writeFile(path.join(output,'capture-range.json'),JSON.stringify({fromMilliseconds:from,toMilliseconds:to,requireNative,requireFence,requireObserver,requireIssuer,captureStartedAt:new Date().toISOString(),deadlineMilliseconds:deadline},null,2)+'\n');
await writeFile(path.join(output,'index.json'),JSON.stringify(index,null,2)+'\n');
const walked=spawnSync(process.execPath,[fileURLToPath(new URL('./walk.cjs',import.meta.url)),specPath],{env:{...process.env,S:output},stdio:'inherit'});
if(metricsError){console.error(metricsError.message);process.exitCode=1;}
else process.exitCode=walked.status ?? 1;
