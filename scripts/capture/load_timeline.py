#!/usr/bin/env python3
"""Capture three bounded Grafana rounds while the exact eight Fortio processes run."""
import argparse
from contextlib import contextmanager
import datetime as dt
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid
from urllib.parse import urlsplit,parse_qs

OFFSETS=(45,135,225)
ROUND_SECONDS=75
MARGIN_SECONDS=15
PANELS=('cmtc-operations-dark','cmtc-operations-light','cmtc-workload-security-dark','cmtc-workload-security-light')
PAGES=(*PANELS,'application-global-service')
QUERIES={
 'selected':'sum by (cluster) (cmtc_namespaces_selected{component="cmtc-controller"})',
 'agents':'sum by (cluster) (cmtc_node_agent_ready{component="cmtc-node-agent"})',
 'enforcement':'max by (cluster) (cmtc_enforcement_available{component="cmtc-controller"})',
}

class Rejected(RuntimeError):pass

def need(ok,message):
    if not ok:raise Rejected(message)

def now_ms():return int(time.time()*1000)
def iso():return dt.datetime.now(dt.timezone.utc).isoformat()
def read_json(path):return json.loads(Path(path).read_text())
def write_json(path,value):Path(path).write_text(json.dumps(value,indent=2)+'\n')
def started_ms(value):
    stamp=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    need(stamp.tzinfo is not None,'Fortio start time must include a timezone')
    return int(stamp.timestamp()*1000)

def publication_files(root,repository=None):
    """Select only public browser evidence; never publish an artifact tree."""
    root=Path(root)
    repository=Path(repository or Path.cwd()).resolve()
    need(root.resolve().is_relative_to(repository/'artifacts'),'publication escapes artifacts/')
    need(not root.is_symlink(),'refusing a symlink evidence directory')
    selected=[]
    def include(source,destination):
        if not source.exists() and not source.is_symlink():return
        need(source.is_file() and not source.is_symlink(),'refusing a non-file publication source')
        selected.append((str(source.resolve()),destination))
    for source in sorted(root.glob('*.png')):include(source,source.name)
    for name in ('walk.log','walk.rc','timeline-results.json','load-manifest.json'):
        include(root/name,name)
    # These exact JSON files contain the public queries, range and browser verdict.
    # Container records, kubeconfigs, arbitrary JSON and subdirectories stay local.
    for number in range(1,4):
        prefix=f'round-{number:02d}';directory=root/prefix
        need(not directory.is_symlink(),'refusing a symlink round directory')
        for name in ('metric-assertions.json','metric-queries.json','capture-range.json','walk-results.json'):
            include(directory/name,prefix+'--'+name)
    return selected

def specs(run_dir):
    run_dir=Path(run_dir);run_id=run_dir.name
    need(re.fullmatch('[a-z0-9-]{1,32}',run_id) is not None,'invalid load run ID')
    found={}
    for line in (run_dir/'streams.tsv').read_text().splitlines():
        row=line.split('\t');need(len(row)==4,'invalid stream row')
        stream,cluster,namespace,target=row;need(stream not in found,'duplicate load stream')
        need(cluster in ('cmtc-a','cmtc-b'),'unknown cluster')
        if stream==cluster+'-shop':
            wanted_namespace='cf2cnp-lab';wanted_target='http://shop.cf2cnp-lab/';qps=20
        else:
            match=re.fullmatch(re.escape(cluster)+r'-mesh-(80|8080|31337)',stream)
            need(match is not None,'unexpected load stream')
            port=match[1];remote='cmtc-b' if cluster=='cmtc-a' else 'cmtc-a'
            wanted_namespace='mesh-example';wanted_target=f'http://rebel-base-{remote}.mesh-example:{port}/';qps=10 if port=='80' else 5
        need(namespace==wanted_namespace and target==wanted_target,'stream destination differs')
        created=read_json(run_dir/(stream+'.job-created.json'))
        need(created['metadata']['name']==f'cmtc-load-{run_id}-{stream}' and created['metadata']['namespace']==namespace,'created Job identity differs')
        created_uid=live(created['metadata'])
        found[stream]={'createdJobUID':created_uid,'stream':stream,'cluster':cluster,'namespace':namespace,'target':target,'qps':qps,'runID':run_id,'jobName':f'cmtc-load-{run_id}-{stream}'}
    expected={c+s for c in ('cmtc-a','cmtc-b') for s in ('-shop','-mesh-80','-mesh-8080','-mesh-31337')}
    need(set(found)==expected,'exactly eight expected streams required')
    return found

def live(meta):
    need(bool(meta.get('uid')) and not meta.get('deletionTimestamp'),'resource is absent, deleting or unpinned')
    return meta['uid']

def pin(job,pod,spec):
    jm,pm=job['metadata'],pod['metadata'];job_uid,pod_uid=live(jm),live(pm)
    need(job_uid==spec['createdJobUID'],'observed Job UID is not the create-response UID')
    need(jm['name']==spec['jobName'] and jm['namespace']==spec['namespace'] and pm['namespace']==spec['namespace'],'job/namespace differs')
    need(jm.get('labels',{}).get('cmtc.io/load-run')==spec['runID'] and jm['labels'].get('cmtc.io/load-stream')==spec['stream'],'load ownership labels differ')
    owners=[o for o in pm.get('ownerReferences',[]) if o.get('controller')]
    need(len(owners)==1 and owners[0].get('kind')=='Job' and owners[0].get('uid')==job_uid,'Pod controller UID differs')
    need(not job['spec'].get('suspend') and not any(c.get('status')=='True' and c.get('type') in ('Complete','Failed') for c in job.get('status',{}).get('conditions',[])),'load job completed, failed or suspended')
    need(not job.get('status',{}).get('failed') and not job.get('status',{}).get('succeeded'),'load job is no longer active')
    wanted=['load','-qps',str(spec['qps']),'-c','2','-t','6m','-nocatchup','-uniform','-json','/results/fortio.json',spec['target']]
    def fortio(containers):
        items=[c for c in containers if c.get('name')=='fortio'];need(len(items)==1,'one Fortio init container required');return items[0]
    template=fortio(job['spec']['template']['spec']['initContainers'])
    actual=fortio(pod['spec']['initContainers'])
    need(template['args']==wanted and actual['args']==wanted,'Fortio arguments/duration/target differ')
    need(template['image']=='fortio/fortio:1.75.3' and actual['image']==template['image'],'Fortio image differs')
    state=fortio(pod.get('status',{}).get('initContainerStatuses',[]))
    need(set(state.get('state',{}))=={'running'} and state.get('containerID') and state.get('imageID') and state.get('restartCount')==0,'Fortio is not the original running init process')
    need(pod.get('status',{}).get('phase') in ('Pending','Running'),'load Pod is terminal')
    need(pod['spec'].get('nodeName'),'load Pod is not assigned to a node')
    need(not any(c.get('name')=='results' and any(k in c.get('state',{}) for k in ('running','terminated')) for c in pod.get('status',{}).get('containerStatuses',[])),'Fortio results container started before capture')
    start=state['state']['running']['startedAt'];started_ms(start)
    return {'jobName':jm['name'],'jobUID':job_uid,'podName':pm['name'],'podUID':pod_uid,'nodeName':pod['spec']['nodeName'],'containerID':state['containerID'],'imageID':state['imageID'],'startedAt':start,'restartCount':state['restartCount']}

def same(frozen,observed):
    need(observed['clusters']==frozen['clusters'],'cluster incarnation changed')
    need(observed['streams']==frozen['streams'],'load Job/Pod/process incarnation changed')

class Reader:
    def __init__(self,expected):self.expected=expected
    def get(self,cluster,namespace,args,deadline):
        left=deadline-time.monotonic();need(left>0,'load observation deadline exhausted')
        command=['kubectl','--context','kind-'+cluster]
        if namespace:command+=['-n',namespace]
        result=subprocess.run(command+['get',*args,'-o','json'],text=True,capture_output=True,timeout=min(5,left),check=True)
        need(time.monotonic()<deadline,'load observation exceeded deadline')
        need(len(result.stdout)<2_000_000,'load observation is too large')
        return json.loads(result.stdout)
    def observe(self,deadline):
        start=now_ms();clusters={}
        for cluster in ('cmtc-a','cmtc-b'):
            clusters[cluster]=live(self.get(cluster,None,['namespace','kube-system'],deadline)['metadata'])
        result={}
        for name,s in self.expected.items():
            job=self.get(s['cluster'],s['namespace'],['job',s['jobName']],deadline)
            pods=self.get(s['cluster'],s['namespace'],['pods','-l','job-name='+s['jobName']],deadline)['items']
            need(len(pods)==1,'exactly one original load Pod required')
            result[name]=pin(job,pods[0],s)
        return {'startedAtMs':start,'finishedAtMs':now_ms(),'clusters':clusters,'streams':result}

def cleanup_owned_capture(env,out):
    """Recover a failed shell cleanup with a separate, bounded owner check."""
    owner=env.get('CMTC_CAPTURE_RUN_ID','')
    need(bool(re.fullmatch(r'[a-zA-Z0-9._-]{1,128}',owner)),'missing capture cleanup owner')
    engine=env.get('CMTC_CAPTURE_ENGINE','docker')
    need(engine in ('docker','podman'),'unknown cleanup engine')
    command=['docker'] if engine=='docker' else ['podman','--connection',env.get('CMTC_PODMAN_CONNECTION','cmtc-ubuntu-build')]
    deadline=time.monotonic()+10
    result={'owner':owner,'removed':[],'confirmedAbsent':False}
    def run(args):
        left=deadline-time.monotonic();need(left>0,'container recovery deadline exhausted')
        reply=subprocess.run(command+args,text=True,capture_output=True,timeout=min(3,left),check=True)
        return reply.stdout.strip()
    def owned():
        values=run(['ps','-a','--no-trunc','--filter','label=security.cmtc.io/capture-run='+owner,'--format','{{.ID}}']).splitlines()
        need(len(values)<=1 and all(re.fullmatch('[0-9a-f]{64}',x) for x in values),'unexpected owned capture container list')
        return values
    try:
        ids=owned()
        cidfile=out/'container.cid'
        if cidfile.exists():
            recorded=cidfile.read_text().strip()
            need(re.fullmatch('[0-9a-f]{64}',recorded) is not None,'invalid capture container record')
            need(not ids or ids==[recorded],'capture container record differs from owner query')
        for cid in ids:
            label=run(['inspect','--format','{{ index .Config.Labels "security.cmtc.io/capture-run" }}',cid])
            need(label==owner,'refusing another capture owner')
            run(['rm','-f',*(['--time','0'] if engine=='podman' else []),cid]);result['removed'].append(cid)
        need(not owned(),'owned capture container still exists')
        result['confirmedAbsent']=True
    except Exception as exc:
        result['error']=str(exc)
        raise
    finally:write_json(out/'container-cleanup-recovery.json',result)

class Capture:
    def __init__(self,repo,out,env):
        self.out=out;self.env=env
        self.log=(out/'capture.log').open('w');self.closed=False
        self.process=subprocess.Popen(['bash','scripts/lab/capture.sh'],cwd=repo,env=env,stdout=self.log,stderr=subprocess.STDOUT,start_new_session=True)
    def poll(self):return self.process.poll()
    def stop(self):
        forced=False
        if self.process.poll() is None:
            try:os.killpg(self.process.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                forced=True
                try:os.killpg(self.process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                self.process.wait(timeout=2)
        if not self.closed:self.log.close();self.closed=True
        if forced or self.process.returncode:
            cleanup_owned_capture(self.env,self.out)

def check_capture(out,from_ms,to_ms,finished_ms):
    page_list=read_json(out/'walk-results.json')['pages'];pages={p['name']:p for p in page_list}
    need(len(page_list)==len(PAGES) and set(pages)==set(PAGES),'expected two dashboards in both themes and the application check')
    need(all(p.get('render')=='passed' for p in page_list),'one or more browser pages failed')
    for page in page_list:
        need(to_ms<=started_ms(page['capturedAt'])<=finished_ms,'page capture timestamp is stale or outside the round')
        if page['name'] in PANELS:
            query=parse_qs(urlsplit(page['url']).query)
            need(query.get('from')==[str(from_ms)] and query.get('to')==[str(to_ms)],'page URL range differs')
    for name in PANELS:
        png=out/(name+'.png');need(png.is_file() and png.read_bytes()[:8]==b'\x89PNG\r\n\x1a\n','expected PNG missing/invalid')
    capture_range=read_json(out/'capture-range.json')
    need(capture_range['fromMilliseconds']==from_ms and capture_range['toMilliseconds']==to_ms,'browser capture range differs')
    metrics=read_json(out/'metric-assertions.json')
    for cluster in ('cmtc-a','cmtc-b'):
        need(metrics['selected'][cluster]>=2 and metrics['agents'][cluster]==2 and metrics['enforcement'][cluster]==0,'Observe metric assertions differ')
    records=read_json(out/'metric-queries.json')
    need(records['queryTimeSeconds']==to_ms/1000,'metric query time differs from capture end')
    observed=started_ms(records['observedAt'])
    need(to_ms<=observed<=finished_ms,'metric observation timestamp is outside capture phase')
    named={}
    for row in records['queries']:
        need(row['name'] not in named,'duplicate metric query name');named[row['name']]=row
        need(to_ms<=started_ms(row['requestedAt'])<=observed,'metric request timestamp is outside capture phase')
        body=row['response'];need(body.get('status')=='success' and not body.get('warnings') and not body.get('infos'),'Prometheus query failed or returned diagnostics')
    for name,query in QUERIES.items():
        need(name in named and named[name]['query']==query,'missing or substituted Observe query')
        vector=named[name]['response']['data']['result']
        need(len(vector)==2 and {x['metric'].get('cluster') for x in vector}=={'cmtc-a','cmtc-b'},'two-cluster Observe query data missing')
        need(all(math.isfinite(float(x['value'][1])) for x in vector),'nonfinite Observe query value')
        for row in vector:
            need(abs(float(row['value'][0])-to_ms/1000)<.001,'Prometheus evaluation timestamp differs')
            need(float(row['value'][1])==float(metrics[name][row['metric']['cluster']]),'raw query and asserted metric values differ')

class Timeline:
    def __init__(self,repo,run_dir,out,reader=None,clock=None,capture_factory=Capture):
        self.repo=Path(repo);self.run_dir=Path(run_dir);self.out=Path(out)
        self.expected=specs(self.run_dir);self.reader=reader or Reader(self.expected)
        self.clock=clock or time;self.capture_factory=capture_factory
    def milliseconds(self):return int(self.clock.time()*1000)
    def observe(self,label,deadline,frozen=None):
        sample=self.reader.observe(deadline)
        if frozen is not None:same(frozen,sample)
        write_json(self.out/(label+'.json'),sample)
        return sample
    def run(self):
        need(not os.environ.get('CMTC_WALK_SPEC'),'load timeline requires the default CMTC dashboard walk')
        self.out.mkdir(parents=True,exist_ok=True)
        need(not (self.out/'load-manifest.json').exists(),'timeline output was already used')
        need(not (self.run_dir/'load-manifest.json').exists(),'load run already has a frozen manifest')
        rounds=[];report={'qualifiedDuringLoad':False,'rounds':rounds,'finalFortioCollectionRequired':True}
        try:
            frozen=self.observe('load-frozen',self.clock.monotonic()+15)
            need(len(frozen['streams'])==8,'exactly eight frozen processes required')
            anchor=self.milliseconds();anchor_mono=self.clock.monotonic();common_from=max(anchor,max(started_ms(p['startedAt']) for p in frozen['streams'].values()))
            need(common_from<=anchor+5000,'node clock is ahead of capture runner')
            earliest_end=min(started_ms(p['startedAt'])+360000 for p in frozen['streams'].values())
            need(anchor+(OFFSETS[-1]+ROUND_SECONDS+MARGIN_SECONDS)*1000<earliest_end,'insufficient common six-minute load window')
            manifest={'observedAt':iso(),'anchorMs':anchor,'commonFromMs':common_from,'earliestExpectedEndMs':earliest_end,'offsetSeconds':OFFSETS,'roundDeadlineSeconds':ROUND_SECONDS,'expected':self.expected,'frozen':frozen}
            write_json(self.out/'load-manifest.json',manifest)
            write_json(self.run_dir/'load-manifest.json',manifest)
            for number,offset in enumerate(OFFSETS,1):
                name=f'round-{number:02d}';child=self.out/name
                need(not child.exists(),'round directory already exists');child.mkdir()
                wait_until=anchor_mono+offset
                while self.clock.monotonic()<wait_until:
                    self.clock.sleep(min(.5,wait_until-self.clock.monotonic()))
                expected_wall=anchor+int((self.clock.monotonic()-anchor_mono)*1000)
                need(abs(self.milliseconds()-expected_wall)<=2000,'runner wall clock changed during timeline')
                deadline=min(self.clock.monotonic()+ROUND_SECONDS,anchor_mono+(earliest_end-anchor)/1000-MARGIN_SECONDS)
                need(deadline>self.clock.monotonic(),'load overlap expired before round')
                record={'round':name,'scheduledOffsetSeconds':offset,'startedAtMs':self.milliseconds(),'passed':False};rounds.append(record)
                pre=self.observe(name+'-pre',deadline,frozen)
                to_ms=self.milliseconds();need(to_ms>common_from,'empty common-active capture window')
                record.update(fromMilliseconds=common_from,toMilliseconds=to_ms)
                env=dict(os.environ,CMTC_CAPTURE_OUT=str(child.relative_to(self.repo)),CMTC_CAPTURE_FROM_MS=str(common_from),CMTC_CAPTURE_TO_MS=str(to_ms),CMTC_CAPTURE_RUN_ID=str(uuid.uuid4()),CMTC_CAPTURE_DEADLINE_MS=str(self.milliseconds()+max(0,int((deadline-self.clock.monotonic())*1000))))
                process=self.capture_factory(self.repo,child,env);next_check=self.clock.monotonic()+5;sample_number=0
                try:
                    while process.poll() is None:
                        need(self.clock.monotonic()<deadline,'capture round exceeded its deadline')
                        if self.clock.monotonic()>=next_check:
                            sample_number+=1;self.observe(name+f'-mid-{sample_number:02d}',deadline,frozen);next_check=self.clock.monotonic()+5
                        self.clock.sleep(.2)
                    need(process.poll()==0,'browser capture returned failure')
                    need(sample_number>=1,'capture finished without a mid-round load observation')
                    self.observe(name+'-post',deadline,frozen)
                    check_capture(child,common_from,to_ms,self.milliseconds())
                    need(self.clock.monotonic()<deadline and self.milliseconds()<earliest_end-MARGIN_SECONDS*1000,'capture completed after safe load window')
                    record.update(passed=True,finishedAtMs=self.milliseconds(),midChecks=sample_number)
                    print(json.dumps({'stage':'during-load-capture',**record}),flush=True)
                finally:
                    process.stop()
                    # Preserve failed-round screenshots for the existing publisher.
                    # Only timeline-results.json determines whether they passed.
                    for source in child.glob('*.png'):
                        need(not source.is_symlink(),'refusing a symlink capture')
                        destination=self.out/(name+'--'+source.name)
                        need(not destination.exists(),'round PNG collision')
                        destination.write_bytes(source.read_bytes())
                    if (child/'capture.log').exists():print((child/'capture.log').read_text(),flush=True)
                    write_json(self.out/'timeline-results.json',report)
            need(len(rounds)==3 and all(r['passed'] for r in rounds),'not all capture rounds passed')
            report['qualifiedDuringLoad']=True
            return report
        except Exception as exc:
            report['error']=str(exc);raise
        finally:write_json(self.out/'timeline-results.json',report)

@contextmanager
def shutdown_handlers():
    """Let graceful CLI cancellation unwind owned capture cleanup."""
    signals=(signal.SIGTERM,signal.SIGINT)
    previous={number:signal.getsignal(number) for number in signals}
    def interrupted(number,frame):
        # Preserve the bounded cleanup interval if cancellation is repeated.
        for item in signals:signal.signal(item,signal.SIG_IGN)
        raise Rejected(f'capture timeline interrupted by signal {number}')
    try:
        for number in signals:signal.signal(number,interrupted)
        yield
    finally:
        for number,handler in previous.items():signal.signal(number,handler)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',required=True);parser.add_argument('--out',required=True)
    args=parser.parse_args();repo=Path.cwd().resolve()
    def local(raw):
        path=Path(raw);need(not path.is_absolute() and path.parts and path.parts[0]=='artifacts' and '..' not in path.parts,'evidence must be under artifacts/')
        resolved=(repo/path).resolve();need(resolved.is_relative_to(repo/'artifacts'),'evidence symlink escapes artifacts/');return resolved
    with shutdown_handlers():
        Timeline(repo,local(args.run_dir),local(args.out)).run()
if __name__=='__main__':main()
