#!/usr/bin/env python3
"""Exact-image fanout plus real packet telemetry; no mTLS/Protected claim.

Copy beside test-fence-fanout.py. Primary may subclass capture_live_evidence;
that callback is deliberately Python-only, with no arbitrary shell hook.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys
import time

LIB=Path(__file__).resolve().parent
sys.path.insert(0,str(LIB))
spec=importlib.util.spec_from_file_location('fence_fanout',LIB/'test-fence-fanout.py')
fanout=importlib.util.module_from_spec(spec); spec.loader.exec_module(fanout)
require=fanout.require
from datapath_capture import capture_datapath


def load_module(path):
    spec=importlib.util.spec_from_file_location('fence_telemetry',path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def targets(items,clusters):
    found={}
    for item in items:
        cluster,separator,url=item.partition('=')
        require(separator and cluster not in found and re.fullmatch(r'https?://[^\s]+',url),'invalid/duplicate CLUSTER=URL')
        found[cluster]=url
    require(set(found)==set(clusters),'target URLs must cover exactly the actual selected clusters')
    return found


class TelemetryFanout(fanout.Fanout):
    def __init__(self,args):
        self.telemetry=load_module(Path(args.telemetry_module))
        self.target_urls=targets(args.targets_prometheus,args.clusters)
        super().__init__(args)
        self.expected={(c,n,'ingress') for c,n in self.routes}
        self.telemetry_out=self.out/'telemetry'; self.telemetry_out.mkdir()
        self.telemetry_sequence=0
        self.report['telemetry']={'scope':'one audited source-veth ingress hook/node; packet counts, not HTTP requests or TLS',
            'centralPrometheus':args.prometheus,'localTargetURLs':self.target_urls,'loadRepetitions':args.load_repetitions,
            'captureStatus':'pending primary capture_live_evidence callback'}
        self.flush()

    def retain(self,name,data):
        self.evidence_sequence=getattr(self,'evidence_sequence',0)+1
        path=self.telemetry_out/(f'{self.evidence_sequence:04d}-'+name+'.json')
        path.write_text(json.dumps(data,indent=2)+'\n')
        return str(path)

    def snapshot(self,name,absent=False,timeout=90):
        deadline=time.monotonic()+timeout; attempt=0
        while True:
            attempt+=1; self.telemetry_sequence+=1
            report={'phase':name,'attempt':attempt,'passed':False}
            try:
                report=self.telemetry.snapshot(self.args.prometheus,self.expected,absent=absent,
                    target_bases=self.target_urls,report=report)
                report['passed']=True
            except Exception as error:
                report['error']=str(error)
                self.retain(f'{self.telemetry_sequence:03d}-{name}-failed',report)
                if time.monotonic()>=deadline: raise
                time.sleep(3); continue
            self.retain(f'{self.telemetry_sequence:03d}-{name}',report)
            return report

    def ledger(self,name):
        records={}
        for (cluster,node),h in self.routes.items():
            phase=h.phase(); chain=h.pin_chain(cluster,phase)
            pin=phase['hostPinRoot']+'/'+phase['key']+'/accounted'
            raw=json.loads(h.agent_exec(cluster,'/usr/local/bin/bpftool','-j','map','show','pinned',pin).stdout)
            if isinstance(raw,list): require(len(raw)==1,'ambiguous actual counter map'); raw=raw[0]
            counts=h.counter_map(cluster,phase)  # Also verifies this map belongs to actual attached program.
            records[cluster+'/'+node+'/ingress']={'mapID':int(raw['id']),'chain':chain,'counts':counts,
                'namespaceUID':phase['config']['namespaceUID'],'podUID':phase['podUID'],
                'imageID':self.args.image_id,'revision':self.args.expected_revision}
        self.retain(name,records); return records

    @staticmethod
    def same_bindings(before,after):
        require(before.keys()==after.keys(),'actual node scope changed')
        for key in before:
            for field in ('mapID','chain','namespaceUID','podUID','imageID','revision'):
                require(before[key][field]==after[key][field],'actual fence binding changed: '+key+'/'+field)

    def raw_endpoints(self):
        records={}
        for (cluster,node),h in self.routes.items():
            obj=h.get(cluster,'node',node)
            require(obj['metadata']['uid']==h.state()['nodeUID'],'Node incarnation changed')
            addresses={a['address'] for a in obj['status']['addresses'] if a['type']=='InternalIP' and ipaddress.ip_address(a['address']).version==4}
            require(len(addresses)==1,'need exact actual IPv4 InternalIP')
            ip=next(iter(addresses)); cases=[]
            for method,path,status in (('GET','/metrics',200),('GET','/healthz',404),('GET','/readyz',404),('GET','/debug/pprof/',404),('POST','/metrics',405)):
                r=h.kubectl(cluster,'-n','mesh-example','exec','mesh-client','--','curl','-sS','--max-time','5',
                    '-X',method,'-w','\n%{http_code}',f'http://{ip}:18084{path}',timeout=10,label='readonly-fence-endpoint-audit')
                body,separator,code=r.stdout.rpartition('\n')
                require(separator and code.isdecimal() and int(code)==status,'wrong metrics-only endpoint status')
                if path=='/metrics' and method=='GET':
                    require(all(family in body for family in self.telemetry.FAMILIES),'metrics response lacks real fence families')
                cases.append({'method':method,'path':path,'status':int(code),'body':body})
            records[cluster+'/'+node]={'nodeUID':obj['metadata']['uid'],'internalIP':ip,'cases':cases}
        self.retain('raw-endpoints',records)

    def selections(self):
        records={}
        for cluster in self.args.clusters:
            expected={key for key in self.expected if key[0]==cluster}
            report={}
            try:
                report=self.telemetry.snapshot(self.args.prometheus,expected,
                    target_bases={cluster:self.target_urls[cluster]},report=report)
            finally: self.retain('selection-'+cluster,report)
            records[cluster]=report
        wrong='cmtc-no-such-cluster-'+self.run_id
        for family in self.telemetry.FAMILIES:
            query=family+self.telemetry.SELECTOR[:-1]+',cluster='+json.dumps(wrong)+'}'
            body=self.telemetry.fetch(self.args.prometheus,'/api/v1/query',{'query':query})
            self.retain('wrong-cluster-'+family,body)
            require(not body['data']['result'],'unknown cluster unexpectedly returned data')
        return records

    def capture_live_evidence(self,start_unix,end_unix):
        capture_datapath(self,start_unix,end_unix,profile="fence")

    def after_all_installed(self):
        start=time.time()
        self.raw_endpoints()
        self.snapshot('all-installed')
        self.selections()
        bindings_before=self.ledger('kernel-before-load')
        before=self.snapshot('before-load')
        def load(h):
            for _ in range(self.args.load_repetitions): h.traffic(h.cluster,h.phase(),True)
        # Each worker owns a separate NodeHarness/report/command ledger. Future
        # errors propagate; a failed route is never counted as successful load.
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures=[pool.submit(load,h) for h in self.routes.values()]
            failures=[]
            for future in futures:
                try: future.result()
                except Exception as error: failures.append(str(error))
        require(not failures,'real per-node HTTP load failed: '+repr(failures))
        self.report['telemetry']['loadHTTPAttempts']=len(self.routes)*6*self.args.load_repetitions
        # Receiver A needs two full successful source scrapes plus remote-write.
        time.sleep(self.args.scrape_seconds*2)
        deadline=time.monotonic()+90
        while True:
            after=self.snapshot('after-load')
            try:
                comparison=self.telemetry.compare(before,after)
                self.retain('actual-load-comparison',comparison); break
            except Exception as error:
                self.retain('load-comparison-failed-'+str(self.telemetry_sequence),{'error':str(error),'before':before,'after':after})
                if time.monotonic()>=deadline: raise
                time.sleep(3)
        bindings_after=self.ledger('kernel-after-load'); self.same_bindings(bindings_before,bindings_after)
        self.loaded_bindings=bindings_after
        for key in bindings_before:
            require(all(bindings_after[key]['counts'][field]>bindings_before[key]['counts'][field] for field in ('packets','bytes')),
                'load missing actual exact-map packet/byte delta: '+key)
        # Quiet evidence uses raw cumulative samples, never rate extrapolation.
        # Bounded retries let outstanding TCP retries settle without fake zeros.
        deadline=time.monotonic()+90
        while True:
            kernel_a=self.ledger('idle-kernel-a'); idle_a=self.snapshot('idle-a')
            time.sleep(max(10,self.args.scrape_seconds))
            kernel_b=self.ledger('idle-kernel-b'); idle_b=self.snapshot('idle-b')
            self.same_bindings(kernel_a,kernel_b)
            try:
                require(all(kernel_a[k]['counts']==kernel_b[k]['counts'] for k in kernel_a),'raw kernel counters not idle')
                self.retain('idle-comparison',self.telemetry.compare(idle_a,idle_b,idle=True)); break
            except Exception as error:
                self.retain('idle-failed-'+str(self.telemetry_sequence),{'error':str(error),'a':idle_a,'b':idle_b})
                if time.monotonic()>=deadline: raise
        self.selections()
        root=LIB.parents[1]
        owner=self.owner(self.args.clusters[0])
        owner.command([sys.executable,str(root/'observability/validate.py'),'--prometheus',self.args.prometheus,
            '--out',str(self.telemetry_out/'dashboard-query-evidence.json')],timeout=240,label='real-dashboard-query-validation')
        self.capture_live_evidence(start,time.time())
        self.report['telemetry']['installedEvidencePassed']=True; self.flush()

    def after_all_removed(self):
        # Require both local discovery inventories empty AND central raw families
        # absent. Pins remain and the base phase already proves real traffic deny.
        self.snapshot('all-removed',absent=True,timeout=90)
        remaining=self.ledger('kernel-after-daemons-removed')
        self.same_bindings(self.loaded_bindings,remaining)
        self.report['telemetry']['absentEvidencePassed']=True; self.flush()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('image','image-id','expected-revision','out','prometheus'): p.add_argument('--'+name,required=True)
    p.add_argument('--targets-prometheus',action='append',required=True,metavar='CLUSTER=URL')
    p.add_argument('--clusters',nargs='+',choices=fanout.lab.CLUSTERS,default=list(fanout.lab.CLUSTERS))
    p.add_argument('--kubeconfig',default='/private/tmp/cmtc-a-b-20261024.kubeconfig')
    p.add_argument('--template',default='config/experimental/datapath-fence-fanout.yaml')
    p.add_argument('--client-image',default=fanout.lab.observer.CURL)
    p.add_argument('--telemetry-module',default=str(LIB.parents[1]/'observability/fence_telemetry.py'))
    p.add_argument('--dashboard-source',default=str(LIB.parents[1]))
    p.add_argument('--capture-runtime',required=True,help='Task-owned npm ci directory using scripts/capture/package-lock.json')
    p.add_argument('--grafana-url',default='http://127.0.0.1:13000')
    p.add_argument('--application-url',default='http://127.0.0.1:18081')
    p.add_argument('--load-repetitions',type=int,choices=(2,3),default=2)
    p.add_argument('--scrape-seconds',type=int,choices=(5,10,15),default=5)
    a=p.parse_args()
    require(len(set(a.clusters))==len(a.clusters),'duplicate actual cluster')
    require(a.image.startswith('localhost/') and '@' not in a.image,'explicit loaded local image required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}',a.image_id),'exact image configuration ID required')
    require(re.fullmatch(r'[0-9a-f]{40}',a.expected_revision),'exact source revision required')
    require(Path(a.kubeconfig).is_file() and Path(a.telemetry_module).is_file(),'owned kubeconfig/accepted telemetry module missing')
    targets(a.targets_prometheus,a.clusters)
    return TelemetryFanout(a).execute()

if __name__=='__main__': sys.exit(main())
