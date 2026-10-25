// Select actual visible panels and explicitly requested expandable diagnostics.
// Collapsed future panels remain in capability evidence even when not rendered.
function allPanels(panels) {
  return panels.flatMap(panel => [panel, ...allPanels(panel.panels || [])]);
}
function capturePlan(dashboard, {requireNative=false, requireFence=false, requireObserver=false}={}) {
  const native=dashboard.uid==='cmtc-authenticated-only';
  const leaves=[]; const actions=[];
  function visit(panels) {
    for(const panel of panels) {
      if(panel.type!=='row') {leaves.push(panel);continue;}
      if(!panel.collapsed) {visit(panel.panels || []);continue;}
      const expand=(native && requireNative && !panel.title.endsWith('· planned')) ||
        (!native && ((requireFence && panel.id===30) || (requireObserver && panel.id===40)));
      if(expand) {actions.push({click:panel.title},{wait:500});visit(panel.panels || []);}
    }
  }
  visit(dashboard.panels);
  const blockedCapabilities=allPanels(dashboard.panels).filter(p=>p.type!=='row' && p.title.endsWith('· planned')).map(p=>p.title);
  if(native && !requireNative) blockedCapabilities.unshift('Combined ClusterMesh workload mTLS: not qualified by this capture');
  return {panels:leaves,actions,blockedCapabilities};
}
module.exports={allPanels,capturePlan};
function emptyReason(panel,uid,{requireNative=false,requireFence=false,requireObserver=false,requireIssuer=false}={}) {
  if(panel.title.endsWith('· planned')) return 'Planned instrumentation; implementation and real scrape qualification are still required.';
  if(uid==='cmtc-observe-lab' && panel.targets?.length) {
    if(panel.id>=30 && panel.id<=36 && !requireFence) return 'Opt-in audited quarantine is not required in this profile; this is not mTLS evidence.';
    if(panel.id>=40 && panel.id<=45 && !requireObserver) return 'Opt-in packet observer is not required in this profile; this is not mTLS evidence.';
  }
  if(uid==='cmtc-authenticated-only' && panel.targets?.length) {
    if(panel.title.includes('telemetry coverage')) return undefined;
    const producer=panel.targets.some(t=>t.expr?.includes('cmtc_issuer_profile'));
    if(producer && !requireIssuer) return 'Optional issuer-profile producer is not required in this profile; publication is not consumption or protection.';
    if(!producer && !requireNative) return 'Combined node-ztunnel workload mTLS is not qualified in this profile.';
  }
  return undefined;
}
module.exports.emptyReason=emptyReason;
