#!/usr/bin/env python3
"""Actual Observe-only TCX telemetry. Native CNP remains the verdict owner."""
import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys
import time

LIB=Path(__file__).resolve().parent
sys.path.insert(0,str(LIB))
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
observer=module('owned_observer',LIB/'test-observer.py')
from datapath_capture import capture_datapath
require=observer.require
CLUSTERS=('cmtc-a','cmtc-b')


def target_urls(items):
    found={}
    for value in items:
        cluster,separator,url=value.partition('=')
        require(separator and cluster not in found and re.fullmatch(r'https?://[^\s]+',url),'invalid/duplicate local target URL')
        found[cluster]=url
    require(set(found)==set(CLUSTERS),'require both actual cluster target URLs')
    return found


def one(value):
    if isinstance(value,list): require(len(value)==1,'ambiguous kernel object');value=value[0]
    require(isinstance(value,dict),'unknown kernel object encoding');return value


def sum_percpu(entries):
    require(isinstance(entries,list) and len(entries)==1,'observer map must have exactly one key')
    entry=entries[0]; values=entry.get('values')
    require(isinstance(values,list) and values,'missing per-CPU map values')
    totals={'packets':0,'bytes':0}
    for cpu in values:
        value=cpu['value']
        if isinstance(value,dict):
            require(set(value)=={'packets','bytes'},'unexpected observer counter fields')
            current={k:int(value[k]) for k in totals}
        else:
            require(isinstance(value,list) and len(value)==16,'unknown observer counter layout')
            raw=bytes(int(v,16) if isinstance(v,str) else v for v in value)
            current={'packets':int.from_bytes(raw[:8],'little'),'bytes':int.from_bytes(raw[8:],'little')}
        require(all(v>=0 for v in current.values()),'negative observer counter')
        for key in totals: totals[key]+=current[key]
    return totals


class ObserverTelemetryHarness(observer.Harness):
    def __init__(self,args):
        self.telemetry=module('actual_fence_telemetry',args.telemetry_module)
        self.target_urls=target_urls(args.targets_prometheus)
        super().__init__(args)
        self.expected={(c,c+'-worker','ingress') for c in CLUSTERS}
        self.evidence=self.out/'telemetry';self.evidence.mkdir();self.telemetry_out=self.evidence;self.sequence=0
        self.report['telemetry']={'profile':'observer','scope':'preverdict packet observation; Cilium owns native policy DENY31337',
            'captureStatus':'not captured; primary callback required'}

    def retain(self,name,data):
        self.sequence+=1;path=self.evidence/(f'{self.sequence:04d}-'+name+'.json')
        path.write_text(json.dumps(data,indent=2)+'\n');return str(path)

    def snapshot(self,name,absent=False,expected=None,timeout=90):
        expected=self.expected if expected is None else expected
        urls={c:self.target_urls[c] for c,n,d in expected}
        deadline=time.monotonic()+timeout
        while True:
            report={'phase':name,'passed':False}
            try:
                report=self.telemetry.snapshot(self.args.prometheus,expected,target_bases=urls,
                    absent=absent,profile='observer',report=report)
                report['passed']=True;self.retain(name,report);return report
            except Exception as error:
                report['error']=str(error);self.retain(name+'-failed',report)
                if time.monotonic()>=deadline:raise
                time.sleep(3)

    def ledger(self,name,clusters=CLUSTERS):
        records={}
        for cluster in clusters:
            state=self.report['clusters'][cluster]
            chain=self.check_chain(cluster,True); program=chain[0]['program']
            info=one(json.loads(self.agent_exec(cluster,'/usr/local/bin/bpftool','-j','prog','show','id',str(program)).stdout))
            require(info['id']==program and info['name']=='cmtc_observe','wrong actual observer program')
            maps=info.get('map_ids',[]);require(len(maps)==1,'unexpected observer program map set')
            mapid=int(maps[0])
            metadata=one(json.loads(self.agent_exec(cluster,'/usr/local/bin/bpftool','-j','map','show','id',str(mapid)).stdout))
            require(metadata['id']==mapid and metadata['name']=='observed' and metadata['type']=='percpu_array' and metadata['max_entries']==1,'wrong actual observer map')
            counts=sum_percpu(json.loads(self.agent_exec(cluster,'/usr/local/bin/bpftool','-j','map','dump','id',str(mapid)).stdout))
            # Existing metrics() obtains the actual local sample, not generated
            # data. Record separately; its periodic refresh can lag raw counters.
            rawmetrics=self.metrics(cluster)
            require(rawmetrics['cmtc_datapath_observer_ready']==1,'raw observer not ready')
            records[cluster+'/'+cluster+'-worker/ingress']={'programID':program,'mapID':mapid,'chain':chain,'counts':counts,
                'localMetrics':rawmetrics,'podUID':state['config']['podUID'],'imageID':self.args.image_id,'revision':self.args.expected_revision}
        self.retain(name,records);return records

    @staticmethod
    def same_bindings(before,after):
        require(before.keys()==after.keys(),'observer scope changed')
        for key in before:
            require(all(before[key][f]==after[key][f] for f in ('programID','mapID','chain','podUID','imageID','revision')),'observer reset/replacement inside exact load or idle boundary')

    def raw_endpoints(self):
        report={}
        for cluster in CLUSTERS:
            node=self.get(cluster,'node',cluster+'-worker')
            require(node['metadata']['uid']==self.report['clusters'][cluster]['nodeUID'],'Node incarnation changed')
            addresses={v['address'] for v in node['status']['addresses'] if v['type']=='InternalIP' and ipaddress.ip_address(v['address']).version==4}
            require(len(addresses)==1,'need exact worker IPv4 InternalIP');ip=next(iter(addresses));cases=[]
            for method,path,expected in (('GET','/metrics',200),('GET','/healthz',404),('GET','/readyz',404),('GET','/debug/pprof/',404),('POST','/metrics',405)):
                output=self.kubectl(cluster,'-n','mesh-example','exec','mesh-client','--','curl','-sS','--max-time','5','-X',method,
                    '-w','\n%{http_code}',f'http://{ip}:18085{path}',timeout=10,label='observer-metrics-only-audit').stdout
                body,sep,status=output.rpartition('\n');require(sep and status==str(expected),'observer metrics endpoint status mismatch')
                if method=='GET' and path=='/metrics':require(all(f in body for f in self.telemetry.OBSERVER_FAMILIES),'missing actual observer metrics')
                cases.append({'method':method,'path':path,'status':int(status),'body':body})
            report[cluster]={'nodeUID':node['metadata']['uid'],'internalIP':ip,'cases':cases}
        self.retain('raw-endpoints',report)

    def selections(self):
        for cluster in CLUSTERS:self.snapshot('selection-'+cluster,expected={e for e in self.expected if e[0]==cluster})
        selector='{job="cmtc",component="cmtc-bpf-observer",cluster="cmtc-absent-'+self.run_id+'"}'
        for family in self.telemetry.OBSERVER_FAMILIES:
            body=self.telemetry.fetch(self.args.prometheus,'/api/v1/query',{'query':family+selector})
            self.retain('wrong-cluster-'+family,body);require(not body['data']['result'],'unknown cluster returned observer data')

    def capture_live_evidence(self,start_unix,end_unix):
        capture_datapath(self,start_unix,end_unix,profile='observer')

    def kill_observer(self,cluster):
        # Preserve the complete existing validated SIGKILL/native-verdict test.
        # Observe maps are unpinned: restart MUST replace map/program, not adopt
        # stale state. Separate this reset boundary from same-map load proof.
        time.sleep(self.args.scrape_seconds*2)
        expected={e for e in self.expected if e[0]==cluster}
        central_before=self.snapshot('before-restart-'+cluster,expected=expected)
        restart_boundary=time.time()
        before=self.ledger('before-restart-kernel-'+cluster,clusters=(cluster,))
        super().kill_observer(cluster)
        after=self.ledger('after-restart-kernel-'+cluster,clusters=(cluster,))
        key=next(iter(before))
        require(before[key]['mapID']!=after[key]['mapID'] and before[key]['programID']!=after[key]['programID'],
            'observer restart did not create new unpinned map/program')
        require(all(after[key]['counts'][f]<before[key]['counts'][f] for f in ('packets','bytes')),
            'new observer map did not demonstrate actual counter reset')
        self.retain('actual-counter-reset-'+cluster,{'before':before,'after':after,
            'scope':'new process/map; do not compare as monotonic same-map load'})
        time.sleep(self.args.scrape_seconds*2)
        deadline=time.monotonic()+90
        selector='{job="cmtc",component="cmtc-bpf-observer",cluster='+json.dumps(cluster)+',node='+json.dumps(cluster+'-worker')+'}'
        while True:
            central_after=self.snapshot('after-restart-'+cluster,expected=expected)
            records={'before':central_before,'after':central_after};complete=True
            window=max(1,int(time.time()-restart_boundary+self.args.scrape_seconds*2))
            for family in self.telemetry.OBSERVER_FAMILIES[1:]:
                complete=complete and central_after['values'][family][key]<central_before['values'][family][key]
                body=self.telemetry.fetch(self.args.prometheus,'/api/v1/query',{'query':'resets('+family+selector+'['+str(window)+'s])'})
                records[family]=body;rows=body['data']['result']
                complete=complete and len(rows)==1 and float(rows[0]['value'][1])>=1
            self.retain('restart-prometheus-reset-'+cluster,records)
            if complete:break
            require(time.monotonic()<deadline,'actual observer reset missing from source/remote-written samples')
            time.sleep(3)

    def after_all_installed(self):
        start=time.time();self.raw_endpoints();self.snapshot('both-installed');self.selections()
        before_kernel=self.ledger('before-load');before=self.snapshot('before-load')
        # Shared Harness command counter/report is deliberately sequential.
        attempts=0
        for cluster in CLUSTERS:attempts+=self.traffic(cluster,'telemetry-load',repetitions=2)
        require(attempts==24,'unexpected observer load matrix')
        self.report['telemetry']['additionalHTTPAttempts']={'total':24,'nativeAllowed':16,'nativePolicyDenied':8}
        time.sleep(self.args.scrape_seconds*2)
        deadline=time.monotonic()+90
        while True:
            after=self.snapshot('after-load')
            try:self.retain('load-comparison',self.telemetry.compare(before,after));break
            except Exception as error:
                self.retain('load-comparison-failed',{'error':str(error)})
                if time.monotonic()>=deadline:raise
                time.sleep(3)
        after_kernel=self.ledger('after-load');self.same_bindings(before_kernel,after_kernel)
        for key in before_kernel:
            require(all(after_kernel[key]['counts'][field]>before_kernel[key]['counts'][field] for field in ('packets','bytes')),'real observer map lacks packet/byte load delta')
        deadline=time.monotonic()+90
        while True:
            ka=self.ledger('idle-kernel-a');a=self.snapshot('idle-a');time.sleep(max(10,self.args.scrape_seconds))
            kb=self.ledger('idle-kernel-b');b=self.snapshot('idle-b');self.same_bindings(ka,kb)
            try:
                require(all(ka[k]['counts']==kb[k]['counts'] for k in ka),'actual observed map not idle')
                for k in kb:
                    metrics=kb[k]['localMetrics']
                    require(metrics['cmtc_datapath_observer_packets_total']==kb[k]['counts']['packets'] and
                        metrics['cmtc_datapath_observer_bytes_total']==kb[k]['counts']['bytes'],'periodic local metrics not caught up to quiet exact map')
                self.retain('idle-comparison',self.telemetry.compare(a,b,idle=True));break
            except Exception as error:
                self.retain('idle-comparison-failed',{'error':str(error)})
                if time.monotonic()>=deadline:raise
        self.selections();self.capture_live_evidence(start,time.time())
        self.report['telemetry']['installedEvidencePassed']=True;self.flush()

    def after_all_removed(self):
        self.snapshot('both-removed',absent=True,timeout=90)
        self.report['telemetry']['absentEvidencePassed']=True;self.flush()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','image-id','expected-revision','out','prometheus'):p.add_argument('--'+name,required=True)
    p.add_argument('--targets-prometheus',action='append',required=True)
    p.add_argument('--kubeconfig',default='/private/tmp/cmtc-a-b-20261024.kubeconfig')
    p.add_argument('--template',default='config/experimental/datapath-observer.yaml')
    p.add_argument('--telemetry-module',default=str(LIB.parents[1]/'observability/fence_telemetry.py'))
    p.add_argument('--dashboard-source',default=str(LIB.parents[1]))
    p.add_argument('--capture-runtime',required=True)
    p.add_argument('--grafana-url',default='http://127.0.0.1:13000')
    p.add_argument('--application-url',default='http://127.0.0.1:18081')
    p.add_argument('--repetitions',type=int,default=4)
    p.add_argument('--scrape-seconds',type=int,choices=(5,10,15),default=5)
    a=p.parse_args()
    require(a.image.startswith('localhost/') and '@' not in a.image,'explicit loaded observer tag required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}',a.image_id),'exact observer config ID required')
    require(re.fullmatch(r'[0-9a-f]{40}',a.expected_revision),'exact observer source revision required')
    require(1<=a.repetitions<=20,'baseline repetitions out of bounds')
    require(Path(a.kubeconfig).is_file() and Path(a.telemetry_module).is_file(),'owned kubeconfig/telemetry module missing')
    target_urls(a.targets_prometheus)
    return ObserverTelemetryHarness(a).execute()

if __name__=='__main__':sys.exit(main())
