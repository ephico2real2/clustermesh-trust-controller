const {chromium}=require('playwright');const fs=require('fs');
(async()=>{
const out='/captures';const range=JSON.parse(fs.readFileSync(out+'/capture-range.json')); const b=await chromium.launch();const p=await b.newPage({viewport:{width:1920,height:4800}});const reports=[];
for(const theme of ['dark','light'])for(const [uid,stem] of [['cmtc-observe-lab','operations'],['cmtc-authenticated-only','security']]){
 await p.goto(`http://127.0.0.1:13000/d/${uid}?kiosk&theme=${theme}&from=${range.fromMilliseconds}&to=${range.toMilliseconds}`,{waitUntil:'networkidle'});await p.waitForTimeout(2500);
 const sections=p.locator('section[data-testid^="data-testid Panel header "]');
 const data=await sections.evaluateAll(ss=>ss.map(s=>({title:s.getAttribute('data-testid').replace('data-testid Panel header ',''),rect:{x:s.getBoundingClientRect().x,y:s.getBoundingClientRect().y,width:s.clientWidth,height:s.clientHeight},text:s.innerText,tables:[...s.querySelectorAll('table')].map(t=>({width:t.scrollWidth,clientWidth:t.clientWidth,rows:t.querySelectorAll('tr').length})),overflows:[...s.querySelectorAll('*')].filter(e=>e.scrollHeight>e.clientHeight+8&&e.clientHeight>30&&/auto|scroll/.test(getComputedStyle(e).overflowY)).map(e=>({role:e.getAttribute('role'),testid:e.getAttribute('data-testid'),client:e.clientHeight,scroll:e.scrollHeight,text:e.innerText.slice(0,70)}))})));
 if(stem==='operations'){
  const ns=sections.filter({has:p.getByText('Namespace decisions by cluster',{exact:true})});
  const table=ns.locator('[role="row"]');
  if(await table.count()) {if(await table.count()<9)throw Error('Namespace table lost a decision row');}
  const decision=data.find(x=>x.title==='Namespace decisions by cluster');if(decision.rect.height<340)throw Error('Namespace table has not refreshed');
  await p.screenshot({path:`${out}/operations-summary.${theme}.png`,clip:{x:0,y:0,width:1920,height:2100}});
  await p.screenshot({path:`${out}/operations-planned.${theme}.png`,clip:{x:0,y:2500,width:1920,height:1700}});
 }else{
  await p.screenshot({path:`${out}/workload-security-summary.${theme}.png`,clip:{x:0,y:0,width:1920,height:1750}});
  await p.screenshot({path:`${out}/workload-security-planned.${theme}.png`,clip:{x:0,y:1750,width:1920,height:2850}});
 }
 for(const x of data){if(x.rect.x<0||x.rect.x+x.rect.width>1920||x.rect.y+x.rect.height>4800)throw Error('Panel clipped: '+x.title);}
 reports.push({uid,theme,range,panels:data});
}
fs.writeFileSync(`${out}/layout-report.json`,JSON.stringify(reports,null,2)+'\n');await b.close();console.log('PASS all panels within viewport; both-theme section captures saved');
})().catch(e=>{console.error(e);process.exit(1)});
