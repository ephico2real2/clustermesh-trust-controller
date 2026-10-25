// Materialize the actual Grafana view before evidence/screenshot. No stitching,
// title unions, fake data, dashboard writes, or expectation reductions.
const PANEL_SELECTOR = 'section[data-testid^="data-testid Panel header "]';
const PREFIX = 'data-testid Panel header ';

function missingTitles(expected, actual) {
  const remaining = new Map();
  for (const title of actual) remaining.set(title, (remaining.get(title) || 0) + 1);
  return expected.filter(title => {
    const count = remaining.get(title) || 0;
    if (!count) return true;
    remaining.set(title, count - 1); return false;
  });
}

async function inspect(page, reset = false) {
  return page.evaluate(({selector,prefix,reset}) => {
    const sections = [...document.querySelectorAll(selector)];
    const roots = new Set([document.body, document.documentElement, document.scrollingElement].filter(Boolean));
    // Only panel ANCESTORS: an internal table can legitimately scroll without
    // making the dashboard/page itself taller.
    for (const section of sections) {
      for (let node = section.parentElement; node; node = node.parentElement) {
        if (/auto|scroll/.test(getComputedStyle(node).overflowY)) roots.add(node);
      }
    }
    if (reset) { window.scrollTo(0,0); for (const root of roots) {root.scrollTop=0; root.scrollLeft=0;} }
    let requiredHeight = innerHeight;
    const scrollers = [];
    for (const node of roots) {
      const rect = node.getBoundingClientRect();
      if (node.scrollHeight > node.clientHeight + 4) {
        const documentRoot = node === document.body || node === document.documentElement || node === document.scrollingElement;
        const chrome = documentRoot ? 0 : Math.max(0,rect.top) + Math.max(0,innerHeight-rect.bottom);
        requiredHeight=Math.max(requiredHeight,Math.ceil(node.scrollHeight+chrome+32));
        scrollers.push({tag:node.tagName,testid:node.getAttribute('data-testid'),clientHeight:node.clientHeight,scrollHeight:node.scrollHeight,top:rect.top});
      }
    }
    const panels = sections.map(section => {
      const rect=section.getBoundingClientRect(); const style=getComputedStyle(section);
      return {title:section.getAttribute('data-testid').slice(prefix.length),top:rect.top,bottom:rect.bottom,left:rect.left,right:rect.right,width:rect.width,height:rect.height,visible:style.display!=='none'&&style.visibility!=='hidden'&&rect.width>0&&rect.height>0};
    });
    return {viewport:{width:innerWidth,height:innerHeight},requiredHeight,scrollers,panels,loading:document.querySelectorAll('[aria-label="Panel loading bar"], [data-testid="Panel loading bar"], .panel-loading').length};
  },{selector:PANEL_SELECTOR,prefix:PREFIX,reset});
}

async function prepareGrafanaDashboard(page, options) {
  const expected=options.expectedTitles;
  if (!Array.isArray(expected)||!expected.length||expected.some(x=>typeof x!=='string'||!x)) throw Error('Grafana capture requires API-derived expected panel titles');
  const maxHeight=options.maxHeight || 16000;
  const deadline=Date.now()+(options.timeoutMs || 60000);
  const original=page.viewportSize();
  if (!original || original.width>3840 || maxHeight<original.height || maxHeight>16000) throw Error('Invalid bounded Grafana viewport');
  const history=[]; let stable=0, lastSignature='';
  while (Date.now()<deadline) {
    const geometry=await inspect(page,true);
    const visible=geometry.panels.filter(x=>x.visible);
    const titles=visible.map(x=>x.title);
    const missing=missingTitles(expected,titles);
    const unexpected=missingTitles(titles,expected);
    const clipped=visible.filter(p=>p.top < -1 || p.left < -1 || p.bottom > geometry.viewport.height+1 || p.right > geometry.viewport.width+1).map(p=>p.title);
    const entry={...geometry,titles,missing,unexpected,clipped};
    history.push(entry);
    if (history.length>120) history.shift();
    if (geometry.requiredHeight>geometry.viewport.height) {
      if (geometry.requiredHeight>maxHeight) {
        const err=Error(`Grafana dashboard needs height${geometry.requiredHeight}, exceeds bounded${maxHeight}`);err.captureGeometry=history;throw err;
      }
      await page.setViewportSize({width:original.width,height:geometry.requiredHeight});
      stable=0;lastSignature='';
    } else if (!missing.length&&!unexpected.length&&!clipped.length&&!geometry.loading) {
      const signature=JSON.stringify(visible.map(p=>[p.title,p.top,p.bottom,p.width,p.height]));
      stable=signature===lastSignature ? stable+1 : 0;
      lastSignature=signature;
      // Three equal fully visible inventories, separated by real browser turns.
      if (stable>=2) return {originalViewport:original,viewport:page.viewportSize(),expectedTitles:expected,geometry:history};
    } else {stable=0;lastSignature='';}
    await page.waitForTimeout(500);
  }
  const last=history.at(-1);
  const err=Error(`Grafana panels not completely materialized: mounted${last?.titles.length || 0}/${expected.length}; missing: ${(last?.missing || []).join(' | ')}; clipped: ${(last?.clipped || []).join(' | ')}`);
  err.captureGeometry=history;throw err;
}

module.exports={PANEL_SELECTOR,missingTitles,inspect,prepareGrafanaDashboard};
