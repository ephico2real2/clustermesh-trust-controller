const {chromium}=require('/opt/cmtc-capture/node_modules/playwright');
const fs=require('fs');
const out='/captures';
const labels=['mTLS · no failure flag','Unauthenticated blocked','Authenticated denied','Unverified · no failure flag','Other failures'];
(async()=>{
 const browser=await chromium.launch({headless:true,args:['--no-sandbox']});const results=[];
 for(const theme of ['dark','light']){
  const page=await browser.newPage({viewport:{width:1920,height:1900}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(`http://127.0.0.1:13000/d/cmtc-authenticated-only?from=1792817142251&to=1792817452353&theme=${theme}`,{waitUntil:'networkidle'});
  await page.waitForTimeout(8000);
  const section=title=>page.locator(`section[data-testid="data-testid Panel header ${title}"]`);
  const pie=section('Completed TCP attempts · share by outcome');const pieBox=await pie.boundingBox();
  const checks=[];
  for(const name of labels){
   const box=await pie.getByText(name,{exact:true}).first().boundingBox();
   if(!box||box.y<pieBox.y||box.y+box.height>pieBox.y+pieBox.height)throw Error(`${theme}: legend clipped: ${name}`);
   checks.push({name,box,fullyWithinPanel:true});
  }
  const caption=section('How to read the connection totals and percentages');const captionBox=await caption.boundingBox();
  const finalText=await caption.getByText('TCP connections ≠ HTTP requests ≠ TLS handshakes.',{exact:true}).boundingBox();
  if(!finalText||finalText.y+finalText.height>captionBox.y+captionBox.height)throw Error(`${theme}: caption clipped`);
  const first=await section('mTLS TCP connections started').boundingBox();
  const clip={x:first.x,y:first.y,width:pieBox.x+pieBox.width-first.x,height:pieBox.y+pieBox.height-first.y};
  await page.screenshot({path:`${out}/tcp-outcomes-${theme}.png`,clip});
  if(errors.length)throw Error(JSON.stringify(errors));
  results.push({theme,legend:checks,captionFits:true,crop:clip,pageErrors:errors});
  await page.close();
 }
 await browser.close();fs.writeFileSync(`${out}/layout-checks.json`,JSON.stringify(results,null,2)+'\n');console.log('PASS all five outcomes and full caption visible in dark and light captures');
})().catch(e=>{console.error(e.message);process.exit(1)});
