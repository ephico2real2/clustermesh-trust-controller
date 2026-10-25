#!/usr/bin/env python3
"""Collect logs only from the eight successfully completed frozen Fortio processes."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
from load_timeline import need,read_json,specs,started_ms,write_json

PIN_FIELDS=('jobName','jobUID','podName','podUID','nodeName','containerID','imageID','startedAt','restartCount')

def one(items,name):
    found=[row for row in items if row.get('name')==name]
    need(len(found)==1,f'exactly one {name} container required')
    return found[0]

def validate(job,pod,expected,frozen):
    """Validate actual running/terminated states; return completion and immutable identity."""
    jm,pm=job['metadata'],pod['metadata'];js=job.get('status',{});ps=pod.get('status',{})
    need(not jm.get('deletionTimestamp') and not pm.get('deletionTimestamp'),'load resource is deleting')
    need(jm['uid']==expected['createdJobUID']==frozen['jobUID'],'Job UID changed')
    need(jm['name']==expected['jobName']==frozen['jobName'] and jm['namespace']==expected['namespace'],'Job identity changed')
    need(pm['name']==frozen['podName'] and pm['uid']==frozen['podUID'] and pm['namespace']==expected['namespace'],'Pod identity changed')
    need(pod['spec']['nodeName']==frozen['nodeName'],'Pod node changed')
    labels=jm.get('labels',{})
    need(labels.get('cmtc.io/load-run')==expected['runID'] and labels.get('cmtc.io/load-stream')==expected['stream'],'Job ownership labels changed')
    owners=[owner for owner in pm.get('ownerReferences',[]) if owner.get('controller')]
    need(len(owners)==1 and owners[0].get('kind')=='Job' and owners[0].get('uid')==frozen['jobUID'],'Pod owner changed')
    need(not job['spec'].get('suspend') and not js.get('failed') and not any(row.get('type')=='Failed' and row.get('status')=='True' for row in js.get('conditions',[])),'Job failed or suspended')
    need(job['spec'].get('parallelism',1)==1 and job['spec'].get('completions',1)==1,'Job execution count changed')
    args=['load','-qps',str(expected['qps']),'-c','2','-t','6m','-nocatchup','-uniform','-json','/results/fortio.json',expected['target']]
    for config in (job['spec']['template']['spec'],pod['spec']):
        fortio=one(config['initContainers'],'fortio')
        need(fortio['image']=='fortio/fortio:1.75.3' and fortio['args']==args,'Fortio configuration changed')
        results=one(config['containers'],'results')
        need(results['image']=='alpine:3.20' and results['command']==['cat','/results/fortio.json'],'results configuration changed')
    fortio=one(ps.get('initContainerStatuses',[]),'fortio')
    for field in ('containerID','imageID','restartCount'):
        need(fortio.get(field)==frozen[field],f'Fortio {field} changed')
    need(frozen['restartCount']==0,'frozen Fortio had a restart')
    state=fortio.get('state',{});need(set(state) in ({'running'},{'terminated'}),'Fortio has no original process state')
    process=state.get('terminated',state.get('running'))
    need(process.get('startedAt')==frozen['startedAt'],'Fortio start time changed')
    terminal=state.get('terminated')
    if terminal is not None:
        need(terminal.get('exitCode')==0 and terminal.get('signal',0)==0,'Fortio terminated unsuccessfully')
        need(terminal.get('containerID',fortio['containerID'])==frozen['containerID'],'terminated Fortio container ID changed')
        need(started_ms(terminal['finishedAt'])>=started_ms(frozen['startedAt']),'Fortio termination precedes start')
    need(ps.get('phase') in ('Pending','Running','Succeeded'),'load Pod failed or has unknown phase')
    result_states=ps.get('containerStatuses',[])
    result_state=one(result_states,'results') if result_states else None
    result_term=None
    if result_state:
        need(result_state.get('restartCount')==0,'results container restarted')
        result_term=result_state.get('state',{}).get('terminated')
        if result_term:
            need(result_term.get('exitCode')==0 and result_term.get('signal',0)==0,'results terminated unsuccessfully')
    complete=bool(terminal and result_term and ps.get('phase')=='Succeeded' and js.get('succeeded')==1 and not js.get('active') and any(row.get('type')=='Complete' and row.get('status')=='True' for row in js.get('conditions',[])))
    identity={field:frozen[field] for field in PIN_FIELDS}
    if complete:
        need(result_state.get('containerID') and result_state.get('imageID'),'results process identity missing')
        need(started_ms(result_term['startedAt'])>=started_ms(terminal['finishedAt']),'results started before Fortio completed')
        need(started_ms(result_term['finishedAt'])>=started_ms(result_term['startedAt']),'results termination precedes start')
        identity.update(fortioTermination=terminal,results=result_state)
    return complete,identity

class Collector:
    def __init__(self,run_dir,manifest,request=None,clock=time):
        self.run_dir=Path(run_dir);self.manifest=read_json(manifest);self.expected=specs(self.run_dir)
        need(self.manifest['expected']==self.expected,'timeline manifest differs from this load run/create responses')
        self.frozen=self.manifest['frozen']
        need(set(self.frozen['streams'])==set(self.expected),'frozen manifest must contain the exact eight streams')
        need(set(self.frozen['clusters'])=={'cmtc-a','cmtc-b'} and all(self.frozen['clusters'].values()),'frozen cluster identities missing')
        for name,spec in self.expected.items():
            pin=self.frozen['streams'][name]
            need(all(field in pin for field in PIN_FIELDS),'incomplete frozen process pin')
            need(pin['jobName']==spec['jobName'] and pin['jobUID']==spec['createdJobUID'] and pin['restartCount']==0,'invalid frozen Job/process pin')
        self.clock=clock;self.request=request or self.kubectl
    def kubectl(self,spec,args,deadline):
        remaining=deadline-self.clock.monotonic();need(remaining>0,'collection deadline exhausted')
        command=['kubectl','--context','kind-'+spec['cluster']]
        if spec.get('namespace'):command+=['-n',spec['namespace']]
        response=subprocess.run(command+args,text=True,capture_output=True,check=True,timeout=min(5,remaining))
        need(self.clock.monotonic()<deadline,'collection command exceeded deadline')
        need(len(response.stdout)<2_000_000,'collection response is too large')
        return response.stdout
    def observe(self,name,deadline):
        spec=self.expected[name];frozen=self.frozen['streams'][name]
        cluster=json.loads(self.request({'cluster':spec['cluster']},['get','namespace','kube-system','-o','json'],deadline))['metadata']
        need(cluster['uid']==self.frozen['clusters'][spec['cluster']] and not cluster.get('deletionTimestamp'),'cluster incarnation changed')
        job=json.loads(self.request(spec,['get','job',spec['jobName'],'-o','json'],deadline))
        pods=json.loads(self.request(spec,['get','pods','-l','job-name='+spec['jobName'],'-o','json'],deadline))['items']
        need(len(pods)==1,'expected one original load Pod')
        complete,identity=validate(job,pods[0],spec,frozen)
        return complete,identity,{'job':job,'pod':pods[0],'cluster':cluster}
    def run(self):
        deadline=self.clock.monotonic()+450
        evidence=Path(tempfile.mkdtemp(prefix='frozen-collection-',dir=self.run_dir))
        report={'verified':False,'streams':{},'evidenceDirectory':str(evidence)}
        staged=[]
        try:
            for name,spec in self.expected.items():
                while True:
                    need(self.clock.monotonic()<deadline,'collection deadline exhausted')
                    complete,before,snapshot=self.observe(name,deadline)
                    if complete:break
                    self.clock.sleep(min(.5,max(0,deadline-self.clock.monotonic())))
                write_json(evidence/(name+'.before.json'),snapshot)
                pod=self.frozen['streams'][name]['podName']
                for container,suffix in (('fortio','.log'),('results','.json')):
                    value=self.request(spec,['logs','pod/'+pod,'-c',container],deadline)
                    (evidence/(name+suffix)).write_text(value)
                    staged.append((evidence/(name+suffix),self.run_dir/(name+suffix)))
                complete,after,snapshot=self.observe(name,deadline)
                write_json(evidence/(name+'.after.json'),snapshot)
                need(complete and before==after,'completed Pod/process changed across log reads')
                report['streams'][name]=after
            need(len(report['streams'])==8,'not all eight frozen processes were collected')
            # Do not replace accepted result files until every stream passed both checks.
            for source,destination in staged:destination.write_bytes(source.read_bytes())
            report['verified']=True
            return report
        except Exception as exc:
            report['error']=str(exc);raise
        finally:write_json(self.run_dir/'frozen-load-collection.json',report)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir',required=True);parser.add_argument('--manifest',required=True)
    args=parser.parse_args()
    Collector(args.run_dir,args.manifest).run()
    print('PASS: collected logs from the same eight frozen, successfully terminated Fortio processes')
if __name__=='__main__':main()
