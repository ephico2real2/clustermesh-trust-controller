import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const base='http://127.0.0.1:3000';
const output=path.resolve('artifacts/screenshots');
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
    await writeFile('artifacts/metric-assertions.json',JSON.stringify(data,null,2)+'\n');
    metricsError=undefined;break;
  }catch(e){metricsError=e;await new Promise(r=>setTimeout(r,2000));}
}
const browser=await chromium.launch({headless:true});
const pages=[];
try{
  const page=await browser.newPage({viewport:{width:1600,height:1100}});
  const dashboards=await api('/api/search?type=dash-db');
  if(dashboards.length!==10)throw Error(`Expected nine domain dashboards and one live evaluation dashboard, got ${dashboards.length}`);
  for(const d of dashboards.sort((a,b)=>a.uid.localeCompare(b.uid))){
    await page.goto(base+d.url+'?kiosk&from=now-15m&to=now',{waitUntil:'networkidle'});
    await page.getByText(d.title,{exact:true}).first().waitFor({timeout:30000}).catch(()=>{});
    await page.waitForTimeout(2500);
    const file=`${d.uid}.png`;
    await page.screenshot({path:path.join(output,file),fullPage:true});
    pages.push({title:d.title,file,uid:d.uid});
  }
  await page.goto('http://127.0.0.1:18080',{waitUntil:'networkidle'});
  if(!(await page.textContent('body')).includes('poc2'))throw Error('Imported remote application screenshot did not show the expected backend');
  await page.screenshot({path:path.join(output,'application-global-service.png'),fullPage:true});
  pages.push({title:'Imported Global Service backend',file:'application-global-service.png'});
}finally{await browser.close();await writeFile('artifacts/screenshots/index.json',JSON.stringify(pages,null,2)+'\n');}
if(metricsError)throw metricsError;
console.log(`Captured ${pages.length} real pages; verified both clusters' telemetry and enforcement-unavailable status.`);
