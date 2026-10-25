"""Query-qualified provisioning and both-theme captures for existing datapath pages."""
import json
from pathlib import Path
import shutil
import sys
import urllib.request


def require(condition,message):
    if not condition: raise AssertionError(message)


def qualify_datapath_queries(evidence,profile):
    """Require every actual cluster selection and expected live panel before writes."""
    require(profile in ("fence","observer"),"unknown datapath capture profile")
    panel_ids=set((32,33,34,35,36) if profile=="fence" else (42,43,44,45))
    rate_ids=set((33,34,35) if profile=="fence" else (43,44))
    expected={"cmtc-a|cmtc-b","cmtc-a","cmtc-b"}
    seen=set()
    for selection in evidence.get("selections",[]):
        # The validator also retains a separate planned-security metadata record.
        if "clusterSelection" not in selection:
            require("queries" not in selection,"unnamed query selection")
            continue
        cluster=selection["clusterSelection"]
        require(cluster in expected and cluster not in seen,"unexpected/duplicate cluster selection")
        seen.add(cluster); found=set()
        for query in selection.get("queries",[]):
            panel=query["panelId"]
            if panel not in panel_ids:continue
            found.add(panel);rows=query["response"]["data"]["result"]
            require(rows,"installed "+profile+" panel query returned no data: "+query["panel"])
            if panel in rate_ids:
                require(any(float(row["value"][1])>0 for row in rows),"load missing from panel: "+query["panel"])
        require(found==panel_ids,"missing "+profile+" panel queries for "+cluster+": "+repr(sorted(panel_ids-found)))
    require(seen==expected,"missing actual cluster query selections: "+repr(sorted(expected-seen)))


def capture_datapath(self,start_unix,end_unix,profile="fence"):
    """Qualify candidate queries, then provision and capture the existing pages."""
    source=Path(self.args.dashboard_source).resolve()
    runtime=Path(self.args.capture_runtime).resolve()
    require((runtime/'node_modules/playwright').is_dir(),'pinned local Playwright runtime missing')
    owner_method=getattr(self,"owner",None)
    owner=owner_method(self.args.clusters[0]) if callable(owner_method) else self
    require(profile in ("fence","observer"),"unknown datapath capture profile")
    query_file=self.telemetry_out/'candidate-dashboard-queries.json'
    owner.command([sys.executable,str(source/'observability/validate.py'),'--prometheus',self.args.prometheus,
        '--out',str(query_file)],timeout=240,label='candidate-real-query-validation')
    query_evidence=json.loads(query_file.read_text())
    qualify_datapath_queries(query_evidence,profile)
    # No dashboard is accepted from a guessed metric name: successful real
    # query evidence above precedes this existing ConfigMap update.
    pages={name:(source/'observability/dashboards'/name).read_text()
        for name in ('operations.json','workload-security.json')}
    current=owner.get('cmtc-a','configmap','cmtc-dashboards','monitoring')
    require(set(current['data'])==set(pages),'unexpected provisioned dashboard keys')
    patch=[{'op':'test','path':'/metadata/uid','value':current['metadata']['uid']},
        {'op':'test','path':'/metadata/resourceVersion','value':current['metadata']['resourceVersion']}]
    for name,body in pages.items():patch.append({'op':'replace','path':'/data/'+name,'value':body})
    patch_file=self.telemetry_out/'dashboard-configmap-patch.json'
    patch_file.write_text(json.dumps(patch)+'\n')
    updated=json.loads(owner.kubectl('cmtc-a','-n','monitoring','patch','configmap','cmtc-dashboards',
        '--type=json','--patch-file',str(patch_file),'-o','json',label='provision-qualified-dashboards').stdout)
    require(updated['metadata']['uid']==current['metadata']['uid'] and updated['data']==pages,'dashboard ConfigMap update differs')
    self.retain('provisioned-dashboard-configmap',updated)

    def grafana_matches():
        observations={}
        for name,body in pages.items():
            expected=json.loads(body)
            with urllib.request.urlopen(self.args.grafana_url.rstrip('/')+'/api/dashboards/uid/'+expected['uid'],timeout=5) as response:
                actual=json.load(response)['dashboard']
            observations[name]=actual
            if any(actual.get(key)!=expected.get(key) for key in ('uid','title','panels','templating')):return False
        return observations
    observations=owner.poll('Grafana provisions exact qualified panel JSON',grafana_matches,timeout=100)
    self.retain('grafana-provisioned-panels',observations)
    for name in ('capture.mjs','walk.cjs','grafana-page.cjs'):
        location=source/'scripts/capture'/name
        if not location.exists():location=Path(__file__).resolve().parents[2]/'scripts/capture'/name
        shutil.copyfile(location,runtime/name)
    # Recheck real source targets and timestamp(metric) central freshness after
    # provisioning; historical rate results do not prove current ingestion.
    self.snapshot('before-capture-freshness')
    screenshots=self.telemetry_out/'screenshots';screenshots.mkdir()
    env={**owner.env,'S':str(screenshots),'CMTC_GRAFANA_URL':self.args.grafana_url,
        'CMTC_APP_URL':self.args.application_url,'CMTC_REQUIRE_FENCE':str(profile=='fence').lower(),
        'CMTC_REQUIRE_OBSERVER':str(profile=='observer').lower(),'CMTC_REQUIRE_NATIVE_MTLS':'false',
        'CMTC_CAPTURE_FROM_MS':str(int(start_unix*1000)),
        'CMTC_CAPTURE_TO_MS':str(int(end_unix*1000))}
    # Reuse the exact repository walker and pinned package on the Mac. No
    # Docker build, second Prometheus or kubeconfig/browser mount is needed.
    original_env=owner.env
    try:
        owner.env=env
        owner.command(['node',str(runtime/'capture.mjs')],timeout=300,label='both-theme-grafana-capture')
    finally:owner.env=original_env
    for theme in ('dark','light'):
        for page in ('operations','workload-security'):
            path=screenshots/f'cmtc-{page}-{theme}.png'
            require(path.is_file() and path.stat().st_size>10000,'missing rendered capture: '+str(path))
    self.report['telemetry']['captureInterval']={'fromUnix':start_unix,'toUnix':end_unix}
    self.report['telemetry']['captureStatus']='captured; primary visual inspection still required'
    self.report['telemetry']['screenshots']=str(screenshots)
    self.flush()
