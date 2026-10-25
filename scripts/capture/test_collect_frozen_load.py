import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import collect_frozen_load as m

class Clock:
    def __init__(self):self.value=0
    def monotonic(self):return self.value
    def sleep(self,seconds):self.value+=seconds

def setup(root):
    run=root/'run1';run.mkdir();lines=[];frozen={};jobs={};pods={}
    for cluster in ('cmtc-a','cmtc-b'):
        for suffix in ('shop','mesh-80','mesh-8080','mesh-31337'):
            name=cluster+'-'+suffix;namespace='cf2cnp-lab' if suffix=='shop' else 'mesh-example'
            port=None if suffix=='shop' else suffix.split('-')[1]
            target='http://shop.cf2cnp-lab/' if port is None else 'http://rebel-base-'+('cmtc-b' if cluster=='cmtc-a' else 'cmtc-a')+'.mesh-example:'+port+'/'
            lines.append('\t'.join((name,cluster,namespace,target)))
            meta={'uid':name+'-job-uid','name':'cmtc-load-run1-'+name,'namespace':namespace,'labels':{'cmtc.io/load-run':'run1','cmtc.io/load-stream':name}}
            m.write_json(run/(name+'.job-created.json'),{'metadata':meta})
            qps=20 if port is None else 10 if port=='80' else 5
            config={'initContainers':[{'name':'fortio','image':'fortio/fortio:1.75.3','args':['load','-qps',str(qps),'-c','2','-t','6m','-nocatchup','-uniform','-json','/results/fortio.json',target]}], 'containers':[{'name':'results','image':'alpine:3.20','command':['cat','/results/fortio.json']}]}
            job={'metadata':meta,'spec':{'template':{'spec':copy.deepcopy(config)}},'status':{'succeeded':1,'conditions':[{'type':'Complete','status':'True'}]}}
            pod={'metadata':{'uid':name+'-pod-uid','name':name+'-pod','namespace':namespace,'ownerReferences':[{'controller':True,'kind':'Job','uid':meta['uid']}]},'spec':{**copy.deepcopy(config),'nodeName':cluster+'-worker'},'status':{'phase':'Succeeded','initContainerStatuses':[{'name':'fortio','containerID':'containerd://'+name,'imageID':'sha256:fortio','restartCount':0,'state':{'terminated':{'exitCode':0,'reason':'Completed','startedAt':'2026-10-25T09:30:00Z','finishedAt':'2026-10-25T09:36:00Z'}}}],'containerStatuses':[{'name':'results','containerID':'containerd://results-'+name,'imageID':'sha256:alpine','restartCount':0,'state':{'terminated':{'exitCode':0,'reason':'Completed','startedAt':'2026-10-25T09:36:00Z','finishedAt':'2026-10-25T09:36:01Z'}}}]}}
            frozen[name]={'jobName':meta['name'],'jobUID':meta['uid'],'podName':pod['metadata']['name'],'podUID':pod['metadata']['uid'],'nodeName':pod['spec']['nodeName'],'containerID':'containerd://'+name,'imageID':'sha256:fortio','startedAt':'2026-10-25T09:30:00Z','restartCount':0}
            jobs[name]=job;pods[name]=pod
    (run/'streams.tsv').write_text('\n'.join(lines)+'\n')
    manifest=root/'load-manifest.json';m.write_json(manifest,{'expected':m.specs(run),'frozen':{'clusters':{'cmtc-a':'cluster-a-uid','cmtc-b':'cluster-b-uid'},'streams':frozen}})
    return run,manifest,jobs,pods

class API:
    def __init__(self,jobs,pods):self.jobs=jobs;self.pods=pods;self.logs=[];self.after_log=None;self.cluster_change=False
    def __call__(self,spec,args,deadline):
        if args[:3]==['get','namespace','kube-system']:
            return json.dumps({'metadata':{'uid':'replaced' if self.cluster_change else 'cluster-'+spec['cluster'][-1]+'-uid'}})
        name=spec['stream']
        if args[:2]==['get','job']:return json.dumps(self.jobs[name])
        if args[:2]==['get','pods']:return json.dumps({'items':[self.pods[name]]})
        if args[0]=='logs':
            assert args[1]=='pod/'+self.pods[name]['metadata']['name']
            self.logs.append((name,args[1],args[3]))
            if self.after_log:self.after_log(name,args[3])
            return '{"measured":"results"}\n' if args[3]=='results' else 'original Fortio log\n'
        raise AssertionError(args)

class Tests(unittest.TestCase):
    def trial(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        run,manifest,jobs,pods=setup(Path(temp.name));api=API(jobs,pods);clock=Clock()
        collector=m.Collector(run,manifest,api,clock)
        return collector,api,clock
    def test_all_eight_original_terminated_processes_are_bracketed_and_collected(self):
        c,api,_=self.trial();result=c.run()
        self.assertTrue(result['verified']);self.assertEqual(len(result['streams']),8);self.assertEqual(len(api.logs),16)
        evidence=Path(result['evidenceDirectory']);self.assertEqual(len(list(evidence.glob('*.before.json'))),8);self.assertEqual(len(list(evidence.glob('*.after.json'))),8)
        self.assertEqual(len(list(c.run_dir.glob('*.log'))),8)
        self.assertTrue(all(target.startswith('pod/') for _,target,_ in api.logs))
    def test_every_frozen_process_identity_change_is_rejected_before_logs(self):
        changes=[lambda j,p:j['metadata'].update(uid='replacement'),lambda j,p:p['metadata'].update(uid='replacement'),lambda j,p:p['metadata'].update(name='replacement'),lambda j,p:p['metadata'].update(deletionTimestamp='now'),lambda j,p:p['metadata']['ownerReferences'][0].update(uid='replacement'),lambda j,p:p['spec'].update(nodeName='replacement'),lambda j,p:p['status']['initContainerStatuses'][0].update(containerID='replacement'),lambda j,p:p['status']['initContainerStatuses'][0].update(imageID='replacement'),lambda j,p:p['status']['initContainerStatuses'][0].update(restartCount=1),lambda j,p:p['status']['initContainerStatuses'][0]['state']['terminated'].update(startedAt='2026-10-25T09:30:01Z')]
        for change in changes:
            with self.subTest(change=change):
                c,api,_=self.trial();name=next(iter(c.expected));change(api.jobs[name],api.pods[name])
                with self.assertRaises(RuntimeError):c.run()
                self.assertEqual(api.logs,[]);self.assertFalse(m.read_json(c.run_dir/'frozen-load-collection.json')['verified'])
    def test_failed_termination_job_and_results_are_not_accepted(self):
        changes=[lambda j,p:p['status']['initContainerStatuses'][0]['state']['terminated'].update(exitCode=1),lambda j,p:p['status']['initContainerStatuses'][0]['state']['terminated'].update(signal=9),lambda j,p:j['status'].update(failed=1),lambda j,p:p['status']['containerStatuses'][0].update(restartCount=1),lambda j,p:p['status']['containerStatuses'][0]['state']['terminated'].update(exitCode=1),lambda j,p:p['spec']['initContainers'][0].update(args=['load','http://different'])]
        for change in changes:
            with self.subTest(change=change):
                c,api,_=self.trial();name=next(iter(c.expected));change(api.jobs[name],api.pods[name])
                with self.assertRaises(RuntimeError):c.run()
                self.assertEqual(api.logs,[])
    def test_replacement_between_log_reads_is_rejected_without_committing_any_logs(self):
        c,api,_=self.trial()
        api.after_log=lambda name,container:api.pods[name]['metadata'].update(uid='replacement')
        with self.assertRaisesRegex(RuntimeError,'Pod identity'):c.run()
        self.assertEqual(len(list(c.run_dir.glob('*.log'))),0)
        self.assertEqual(len(api.logs),2)
        self.assertFalse(m.read_json(c.run_dir/'frozen-load-collection.json')['verified'])
    def test_same_pod_results_process_replacement_across_reads_is_rejected(self):
        c,api,_=self.trial()
        api.after_log=lambda name,container:api.pods[name]['status']['containerStatuses'][0].update(containerID='replacement')
        with self.assertRaisesRegex(RuntimeError,'changed across log reads'):c.run()
    def test_cluster_replacement_is_rejected(self):
        c,api,_=self.trial();api.cluster_change=True
        with self.assertRaisesRegex(RuntimeError,'cluster incarnation'):c.run()
        self.assertEqual(api.logs,[])
    def test_running_process_wait_is_bounded_and_never_rewritten_as_terminated(self):
        c,api,clock=self.trial();name=next(iter(c.expected));pod=api.pods[name]
        pod['status']['phase']='Pending';pod['status']['initContainerStatuses'][0]['state']={'running':{'startedAt':'2026-10-25T09:30:00Z'}};pod['status']['containerStatuses']=[]
        with self.assertRaisesRegex(RuntimeError,'deadline'):c.run()
        self.assertEqual(api.logs,[]);self.assertLessEqual(clock.monotonic(),450)
        self.assertEqual(set(pod['status']['initContainerStatuses'][0]['state']),{'running'})
    def test_manifest_must_match_create_responses_and_exact_eight(self):
        c,api,_=self.trial();manifest=c.run_dir.parent/'load-manifest.json'
        data=m.read_json(manifest);data['expected'][next(iter(data['expected']))]['createdJobUID']='replacement';m.write_json(manifest,data)
        with self.assertRaisesRegex(RuntimeError,'create responses'):m.Collector(c.run_dir,manifest,api)
        c,api,_=self.trial();manifest=c.run_dir.parent/'load-manifest.json';data=m.read_json(manifest);data['frozen']['streams'].pop(next(iter(data['frozen']['streams'])));m.write_json(manifest,data)
        with self.assertRaisesRegex(RuntimeError,'exact eight'):m.Collector(c.run_dir,manifest,api)
    def test_api_calls_use_one_global_deadline_and_per_command_bound(self):
        c,api,clock=self.trial()
        response=type('Response',(),{'stdout':'{}'})()
        with patch.object(m.subprocess,'run',return_value=response) as called:
            c.kubectl({'cluster':'cmtc-a','namespace':'mesh-example'},['get','pod','exact'],2)
        self.assertEqual(called.call_args.kwargs['timeout'],2)
        self.assertEqual(called.call_args.args[0][:5],['kubectl','--context','kind-cmtc-a','-n','mesh-example'])
        clock.value=3
        with patch.object(m.subprocess,'run') as called,self.assertRaises(RuntimeError):c.kubectl({'cluster':'cmtc-a'},['get','pod','exact'],2)
        called.assert_not_called()
if __name__=='__main__':unittest.main()
