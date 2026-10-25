const assert=require('node:assert/strict');
const http=require('node:http');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawn}=require('node:child_process');
const {chromium}=require('playwright');
const {prepareGrafanaDashboard,inspect,missingTitles}=require('./grafana-page.cjs');

const titles=Array.from({length:39},(_,i)=>`Panel ${i+1}`);
const html=`<!doctype html><style>html,body{margin:0;height:100%;overflow:hidden}header{height:60px}#scroll{height:calc(100vh - 60px);overflow:auto}#grid{position:relative;height:5772px}section{position:absolute;left:12px;right:12px;height:130px;background:#eee}#inner{height:30px;overflow:auto}</style><header>Virtual dashboard</header><div id="scroll"><div id="grid"></div></div><script>
const params=new URLSearchParams(location.search),box=document.getElementById('scroll'),grid=document.getElementById('grid');
if(params.has('tall'))grid.style.height='20000px';
function render(){grid.replaceChildren();for(let i=0;i<39;i++){if(params.has('missing')&&i===38)continue;const y=i*148;if(y>=box.scrollTop-130&&y<box.scrollTop+box.clientHeight){let s=document.createElement('section');s.setAttribute('data-testid','data-testid Panel header Panel '+(i+1));s.style.top=y+'px';s.innerHTML='<h2>Panel '+(i+1)+'</h2><div id="inner"><div style="height:10000px">4</div></div>';grid.appendChild(s)}}}
box.addEventListener('scroll',()=>requestAnimationFrame(render));addEventListener('resize',()=>requestAnimationFrame(render));render();
</script>`;
const server=http.createServer((req,res)=>{res.writeHead(200,{'Content-Type':'text/html'});res.end(html)});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const browser=await chromium.launch();
 try{
  const page=await browser.newPage({viewport:{width:1920,height:4800}});
  const url=`http://127.0.0.1:${server.address().port}`;
  await page.goto(url);const initial=await inspect(page);assert(initial.panels.length<39,'fixture must actually virtualize');
  const result=await prepareGrafanaDashboard(page,{expectedTitles:titles,maxHeight:6000,timeoutMs:5000});
  const full=await inspect(page);assert.equal(full.panels.length,39);assert(result.viewport.height>4800);assert(result.viewport.height<=6000);
  assert(full.panels.every(p=>p.visible&&p.top>=0&&p.bottom<=result.viewport.height));assert.deepEqual(missingTitles(titles,full.panels.map(p=>p.title)),[]);
  assert.deepEqual(missingTitles(['same','same'],['same']),['same'],'duplicate titles are a multiset');
  await page.setViewportSize({width:1920,height:4800});await page.goto(url+'/?missing=1');
  await assert.rejects(()=>prepareGrafanaDashboard(page,{expectedTitles:titles,maxHeight:6000,timeoutMs:1800}),e=>e.message.includes('Panel 39')&&e.captureGeometry.length>0);
  await page.setViewportSize({width:1920,height:4800});await page.goto(url+'/?tall=1');
  await assert.rejects(()=>prepareGrafanaDashboard(page,{expectedTitles:titles,maxHeight:6000,timeoutMs:1800}),e=>e.message.includes('exceeds bounded6000')&&e.captureGeometry.length>0);
  const stage=fs.mkdtempSync(path.join(os.tmpdir(),'cmtc-virtual-walk-'));
  try{
   async function walk(missing){
    const out=path.join(stage,missing?'missing':'complete');fs.mkdirSync(out);
    const spec={viewport:{width:1920,height:4800},pages:[{name:'fixture',url:url+(missing?'/?missing=1':''),grafanaFullPage:true,grafanaMaxHeight:6000,grafanaTimeoutMs:1800,fullPage:true,evidence:'panels',settle:false,before:1,expect:{panelsMin:39,panelTitles:titles,noDataAllowed:[]}}]};
    const file=path.join(out,'walk.json');fs.writeFileSync(file,JSON.stringify(spec));
    return new Promise((resolve,reject)=>{const child=spawn(process.execPath,[path.join(__dirname,'walk.cjs'),file],{env:{...process.env,S:out}});let log='';child.stdout.on('data',x=>log+=x);child.stderr.on('data',x=>log+=x);child.on('error',reject);child.on('close',code=>resolve({code,log,out}));});
   }
   const success=await walk(false);assert.equal(success.code,0,success.log);assert.match(success.log,/panels=39/);
   assert(fs.statSync(path.join(success.out,'fixture.png')).size>0);
   const failure=await walk(true);assert.equal(failure.code,2,failure.log);assert.match(failure.log,/Panel 39/);
   assert(fs.existsSync(path.join(failure.out,'fixture-geometry-failed.json')));
   assert(fs.existsSync(path.join(failure.out,'fixture-failed.png')));
  }finally{fs.rmSync(stage,{recursive:true,force:true})}
  console.log('PASS actual virtualized browser fixture:39 simultaneously visible, nested table overflow ignored, missing panel rejected, oversized page rejected, duplicate title counts retained');
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1}).finally(()=>server.close());
