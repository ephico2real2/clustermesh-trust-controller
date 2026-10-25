const {chromium}=require('playwright');
const fs=require('fs');
const path=require('path');
const {prepareGrafanaDashboard}=require('./grafana-page.cjs');
(async()=>{
 const dir=process.argv[2],profile=process.argv[3];
 if(!['fence','observer'].includes(profile))throw Error('explicit audited profile required');
 const spec=JSON.parse(fs.readFileSync(path.join(dir,'walk-spec.json'),'utf8'));
 const b=await chromium.launch();
 try{
  const page=await b.newPage({viewport:spec.viewport});
  const report=[];
  for(const theme of ['dark','light']){
   const entry=spec.pages.find(p=>p.name===`cmtc-operations-${theme}`);
   await page.setViewportSize(spec.viewport);
   await page.goto(entry.url,{waitUntil:'load'});
   const geometry=await prepareGrafanaDashboard(page,{expectedTitles:entry.expect.panelTitles});
   const titles=profile==='fence'?['Packet counters and quarantine scope','Audited quarantine · latest by node','Packets rejected by audited quarantine/s','Quarantine rejected packets · selected range','skb bytes rejected by quarantine/s','Fence metrics targets · latest reachability']:['Read observation separately from quarantine','Audited observer · latest by node','Packets observed before Cilium verdict/s','skb bytes observed before Cilium verdict/s','Observer metrics targets · latest reachability'];
   const bounds=[];
   for(const title of titles){
    const panel=page.getByTestId('data-testid Panel header '+title);
    if(await panel.count()!==1)throw Error('panel missing or ambiguous: '+title);
    bounds.push(await panel.boundingBox());
   }
   const y=Math.max(0,Math.floor(Math.min(...bounds.map(b=>b.y))-8));
   const bottom=Math.ceil(Math.max(...bounds.map(b=>b.y+b.height))+8);
   const file=`cmtc-${profile}-section-${theme}.png`;
   await page.screenshot({path:path.join(dir,file),clip:{x:0,y,width:spec.viewport.width,height:bottom-y}});
   report.push({file,url:entry.url,profile,theme,clip:{x:0,y,width:spec.viewport.width,height:bottom-y},titles,geometry});
  }
  fs.writeFileSync(path.join(dir,`${profile}-section-evidence.json`),JSON.stringify(report,null,2)+'\n');
 }finally{await b.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
