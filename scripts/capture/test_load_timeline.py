import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest
from urllib.parse import urlencode
from unittest.mock import Mock,patch

spec=importlib.util.spec_from_file_location('timeline',Path(__file__).with_name('load_timeline.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Clock:
    def __init__(self):self.value=0.
    def monotonic(self):return self.value
    def time(self):return self.value
    def sleep(self,seconds):self.value+=seconds

def fixtures(spec):
    job={'metadata':{'uid':'job-uid','name':spec['jobName'],'namespace':spec['namespace'],'labels':{'cmtc.io/load-run':spec['runID'],'cmtc.io/load-stream':spec['stream']}},'spec':{'template':{'spec':{'initContainers':[{'name':'fortio','image':'fortio/fortio:1.75.3','args':['load','-qps',str(spec['qps']),'-c','2','-t','6m','-nocatchup','-uniform','-json','/results/fortio.json',spec['target']]}]}}},'status':{'active':1}}
    pod={'metadata':{'uid':'pod-uid','name':'fortio-pod','namespace':spec['namespace'],'ownerReferences':[{'controller':True,'kind':'Job','uid':'job-uid'}]},'spec':{'nodeName':'node-a','initContainers':copy.deepcopy(job['spec']['template']['spec']['initContainers'])},'status':{'phase':'Pending','initContainerStatuses':[{'name':'fortio','containerID':'containerd://original','imageID':'sha256:image','restartCount':0,'state':{'running':{'startedAt':'1970-01-01T00:00:00Z'}}}]}}
    return job,pod

def setup_run(repo):
    run_dir=repo/'artifacts/load/run1';run_dir.mkdir(parents=True)
    lines=[]
    for c in ('cmtc-a','cmtc-b'):
        for suffix in ('shop','mesh-80','mesh-8080','mesh-31337'):
            stream=c+'-'+suffix;ns='cf2cnp-lab' if suffix=='shop' else 'mesh-example'
            target='http://shop.cf2cnp-lab/' if suffix=='shop' else 'http://rebel-base-'+('cmtc-b' if c=='cmtc-a' else 'cmtc-a')+'.mesh-example:'+suffix.split('-')[1]+'/'
            lines.append('\t'.join([stream,c,ns,target]))
            m.write_json(run_dir/(stream+'.job-created.json'),{'metadata':{'uid':'job-uid','name':'cmtc-load-run1-'+stream,'namespace':ns}})
    (run_dir/'streams.tsv').write_text('\n'.join(lines)+'\n');return run_dir

class Reader:
    def __init__(self,clock,expected,mutate_at=None,old=False):self.clock=clock;self.expected=expected;self.calls=0;self.mutate_at=mutate_at;self.old=old
    def observe(self,deadline):
        self.calls+=1;self.clock.sleep(.1)
        streams={name:m.pin(*fixtures(s),s) for name,s in self.expected.items()}
        if self.old:
            for row in streams.values():row['startedAt']='1969-12-31T23:58:00Z'
        if self.calls==self.mutate_at:next(iter(streams.values()))['containerID']='replaced'
        return {'startedAtMs':int(self.clock.time()*1000),'finishedAtMs':int(self.clock.time()*1000),'clusters':{'cmtc-a':'cluster-a','cmtc-b':'cluster-b'},'streams':streams}

class FakeCapture:
    def __init__(self,clock,out,env,mode='pass'):
        self.clock=clock;self.start=clock.monotonic();self.mode=mode;self.stopped=False
        start,end=int(env['CMTC_CAPTURE_FROM_MS']),int(env['CMTC_CAPTURE_TO_MS'])
        stamp=m.dt.datetime.fromtimestamp((end+(1 if mode!='stale' else -1000))/1000,m.dt.timezone.utc).isoformat()
        pages=[{'name':name,'render':'passed','featureEvidence':'blocked','capturedAt':stamp,'url':'http://grafana/?'+urlencode({'from':start,'to':end})} for name in m.PAGES]
        if mode=='missing-theme':pages=[p for p in pages if p['name']!='cmtc-operations-light']
        m.write_json(out/'walk-results.json',{'pages':pages})
        for name in m.PANELS:(out/(name+'.png')).write_bytes(b'\x89PNG\r\n\x1a\nmock')
        m.write_json(out/'capture-range.json',{'fromMilliseconds':start,'toMilliseconds':end})
        metrics={name:{'cmtc-a':value,'cmtc-b':value} for name,value in [('selected',2),('agents',2),('enforcement',0)]}
        m.write_json(out/'metric-assertions.json',metrics)
        rows=[{'name':name,'requestedAt':stamp,'query':query,'response':{'status':'success','data':{'result':[{'metric':{'cluster':c},'value':[end/1000,'0' if name=='enforcement' else '2']} for c in ('cmtc-a','cmtc-b')]}}} for name,query in m.QUERIES.items()]
        if mode=='query-empty':rows[0]['response']['data']['result']=[]
        if mode=='query-stale':rows[0]['response']['data']['result'][0]['value'][0]-=60
        if mode=='query-mismatch':rows[0]['response']['data']['result'][0]['value'][1]='999'
        if mode=='request-stale':rows[0]['requestedAt']='1969-01-01T00:00:00Z'
        m.write_json(out/'metric-queries.json',{'observedAt':stamp,'queryTimeSeconds':end/1000,'queries':rows})
        (out/'capture.log').write_text('fake capture log\n')
    def poll(self):
        if self.mode=='hang' or self.clock.monotonic()-self.start<6:return None
        return 2 if self.mode=='browser-fail' else 0
    def stop(self):self.stopped=True

class Tests(unittest.TestCase):
    def test_exact_job_pod_and_init_process_guards(self):
        s={'createdJobUID':'job-uid','jobName':'job','namespace':'ns','runID':'run','stream':'stream','qps':5,'target':'http://target/'}
        j,p=fixtures(s);self.assertEqual(m.pin(j,p,s)['podUID'],'pod-uid')
        changes=[lambda j,p:j['metadata'].update(uid='new-job'),lambda j,p:p['metadata'].update(deletionTimestamp='now'),lambda j,p:p['metadata']['ownerReferences'][0].update(uid='other'),lambda j,p:j['status'].update(succeeded=1),lambda j,p:j['spec'].update(suspend=True),lambda j,p:p['status'].update(phase='Succeeded'),lambda j,p:p['status']['initContainerStatuses'][0].update(state={'terminated':{'exitCode':0}}),lambda j,p:p['status']['initContainerStatuses'][0].update(restartCount=1),lambda j,p:p['spec']['initContainers'][0].update(args=['load','http://wrong']),lambda j,p:j['metadata']['labels'].update({'cmtc.io/load-run':'other'})]
        for change in changes:
            a,b=copy.deepcopy(j),copy.deepcopy(p);change(a,b)
            with self.subTest(change=change),self.assertRaises(m.Rejected):m.pin(a,b,s)
    def test_same_rejects_every_incarnation_change(self):
        a={'clusters':{'cmtc-a':'original'},'streams':{'stream':{'jobUID':'job','podUID':'pod','containerID':'container','imageID':'image','startedAt':'start','nodeName':'node'}}}
        for key in a['streams']['stream']:
            b=copy.deepcopy(a);b['streams']['stream'][key]='replacement'
            with self.subTest(key=key),self.assertRaises(m.Rejected):m.same(a,b)
        b=copy.deepcopy(a);b['clusters']['cmtc-a']='new'
        with self.assertRaises(m.Rejected):m.same(a,b)
    def trial(self,mode='pass',mutate_at=None,old=False):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);repo=Path(temp.name)
        run=setup_run(repo);clock=Clock();reader=Reader(clock,m.specs(run),mutate_at,old);captures=[]
        def capture(repository,out,env):
            self.assertLess(int(env['CMTC_CAPTURE_FROM_MS']),int(env['CMTC_CAPTURE_TO_MS']))
            self.assertGreater(int(env['CMTC_CAPTURE_DEADLINE_MS']),int(env['CMTC_CAPTURE_TO_MS']))
            c=FakeCapture(clock,out,env,mode);captures.append(c);return c
        timeline=m.Timeline(repo,run,repo/'artifacts/screenshots',reader,clock,capture)
        return timeline,captures,clock,reader
    def test_three_rounds_have_both_themes_exact_load_pins_and_distinct_pngs(self):
        t,captures,clock,reader=self.trial()
        result=t.run();self.assertTrue(result['qualifiedDuringLoad']);self.assertTrue(result['finalFortioCollectionRequired'])
        self.assertEqual(len(list(t.out.glob('round-*--*.png'))),12);self.assertEqual(len(captures),3);self.assertTrue(all(c.stopped for c in captures))
        self.assertEqual([r['scheduledOffsetSeconds'] for r in result['rounds']],[45,135,225]);self.assertTrue(all(r['midChecks']>=1 for r in result['rounds']))
        self.assertEqual(len(list(t.out.glob('round-*-pre.json'))),3);self.assertEqual(len(list(t.out.glob('round-*-post.json'))),3)
    def test_mid_round_replacement_stops_capture_and_never_passes(self):
        t,captures,clock,reader=self.trial(mutate_at=3)
        with self.assertRaises(m.Rejected):t.run()
        self.assertTrue(captures[0].stopped);self.assertFalse(m.read_json(t.out/'timeline-results.json')['qualifiedDuringLoad'])
        self.assertEqual(len(list(t.out.glob('round-01--*.png'))),4)
    def test_missing_theme_stale_png_empty_query_and_browser_failure_are_fatal(self):
        for mode in ['missing-theme','stale','query-empty','query-stale','query-mismatch','request-stale','browser-fail']:
            t,captures,clock,reader=self.trial(mode)
            with self.subTest(mode=mode),self.assertRaises(m.Rejected):t.run()
            self.assertTrue(captures[0].stopped);self.assertFalse(m.read_json(t.out/'timeline-results.json')['qualifiedDuringLoad'])
    def test_timeout_stops_only_owned_capture_and_is_not_a_success(self):
        t,captures,clock,reader=self.trial('hang')
        with self.assertRaisesRegex(m.Rejected,'deadline'):t.run()
        self.assertTrue(captures[0].stopped);self.assertLess(clock.time(),125)
        self.assertFalse(m.read_json(t.out/'timeline-results.json')['qualifiedDuringLoad'])
    def test_wall_clock_jump_refuses_before_capture(self):
        t,captures,clock,reader=self.trial()
        clock.time=lambda:clock.value+(60 if clock.value>40 else 0)
        with self.assertRaisesRegex(m.Rejected,'wall clock'):t.run()
        self.assertEqual(captures,[])
        self.assertFalse(m.read_json(t.out/'timeline-results.json')['qualifiedDuringLoad'])
    def test_old_common_window_refuses_before_capture(self):
        t,captures,clock,reader=self.trial(old=True)
        with self.assertRaisesRegex(m.Rejected,'common six-minute'):t.run()
        self.assertEqual(captures,[]);self.assertFalse(m.read_json(t.out/'timeline-results.json')['qualifiedDuringLoad'])
    def test_manifest_requires_eight_unique_specs_and_create_responses(self):
        with tempfile.TemporaryDirectory() as directory:
            run=setup_run(Path(directory));self.assertEqual(len(m.specs(run)),8)
            content=(run/'streams.tsv').read_text();(run/'streams.tsv').write_text(content+content.splitlines()[0]+'\n')
            with self.assertRaises(m.Rejected):m.specs(run)
            (run/'streams.tsv').write_text('\n'.join(content.splitlines()[:-1])+'\n')
            with self.assertRaises(m.Rejected):m.specs(run)
            (run/'streams.tsv').write_text(content)
            path=next(run.glob('*.job-created.json'));body=m.read_json(path);body['metadata']['name']='unowned';m.write_json(path,body)
            with self.assertRaises(m.Rejected):m.specs(run)
    def test_custom_walk_and_existing_timeline_output_are_refused(self):
        t,*_=self.trial()
        with patch.dict(m.os.environ,{'CMTC_WALK_SPEC':'unqualified.json'}),self.assertRaises(m.Rejected):t.run()
        t.run()
        with self.assertRaises(m.Rejected):t.run()
    def test_publication_preserves_failed_round_evidence_without_publishing_private_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory);out=repo/'artifacts/screenshots';out.mkdir(parents=True)
            (out/'timeline-results.json').write_text('{"qualifiedDuringLoad":false}')
            (out/'walk.log').write_text('FAILED before first PNG\n')
            (out/'walk.rc').write_text('1\n')
            (out/'load-manifest.json').write_text('{}')
            (out/'kubeconfig').write_text('private')
            (out/'credentials.json').write_text('{"private":"value"}')
            (out/'container.cid').write_text('private container record')
            child=out/'round-01';child.mkdir()
            for name in ('metric-assertions.json','metric-queries.json','capture-range.json','walk-results.json'):
                (child/name).write_text('{}')
            (child/'container-inspect.json').write_text('{"environment":"private"}')
            files=m.publication_files(out,repo);names={destination for _,destination in files}
            self.assertEqual(names,{'timeline-results.json','load-manifest.json','walk.log','walk.rc',
                'round-01--metric-assertions.json','round-01--metric-queries.json',
                'round-01--capture-range.json','round-01--walk-results.json'})
            (out/'round-01--cmtc-operations-dark.png').write_bytes(b'\x89PNG\r\n\x1a\nmock')
            self.assertIn('round-01--cmtc-operations-dark.png',{name for _,name in m.publication_files(out,repo)})
    def test_publication_rejects_outside_artifacts_and_symlink_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            repo=Path(directory);out=repo/'artifacts/screenshots';out.mkdir(parents=True)
            private=repo/'private.json';private.write_text('private')
            with self.assertRaises(m.Rejected):m.publication_files(repo,repo)
            (out/'timeline-results.json').symlink_to(private)
            with self.assertRaises(m.Rejected):m.publication_files(out,repo)
            (out/'timeline-results.json').unlink()
            (out/'round-01').symlink_to(repo,target_is_directory=True)
            with self.assertRaises(m.Rejected):m.publication_files(out,repo)
    def test_action_selects_timeline_or_single_walk_and_retains_failure_verdict(self):
        action=Path(__file__).resolve().parents[2]/'.github/actions/browser-walk/action.yml'
        body=action.read_text().split('      run: |\n',1)[1].split('\n    - ',1)[0]
        script=textwrap.dedent(body)
        for enabled,wanted_rc,wanted_log in [('true','7','timeline --run-dir artifacts/load/run1 --out artifacts/screenshots'),('false','3','single walk'),('invalid','2','load-timeline must be true or false')]:
            with self.subTest(enabled=enabled),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);(root/'bin').mkdir();(root/'scripts/lab').mkdir(parents=True);(root/'artifacts/load').mkdir(parents=True)
                (root/'artifacts/load/current-run').write_text('run1\n')
                python=root/'bin/python3';python.write_text('#!/bin/bash\necho "timeline ${@:2}"\nexit 7\n');python.chmod(0o755)
                (root/'scripts/lab/capture.sh').write_text('echo "single walk"\nexit 3\n')
                env=dict(os.environ,PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],CMTC_CAPTURE_OUT='artifacts/screenshots',CMTC_LOAD_TIMELINE=enabled)
                result=subprocess.run(['bash','-c',script],cwd=root,env=env,capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((root/'artifacts/screenshots/walk.rc').read_text().strip(),wanted_rc)
                self.assertIn(wanted_log,(root/'artifacts/screenshots/walk.log').read_text())

CID='a'*64
OWNER='own-test-capture'
class CleanupTests(unittest.TestCase):
    def run_cleanup(self,replies,engine='docker',record=CID):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);out=Path(temp.name)
        if record is not None:(out/'container.cid').write_text(record)
        env={'CMTC_CAPTURE_RUN_ID':OWNER,'CMTC_CAPTURE_ENGINE':engine,'CMTC_PODMAN_CONNECTION':'explicit-test-VM'}
        def reply(command,**kwargs):
            self.assertGreater(kwargs['timeout'],0);self.assertLessEqual(kwargs['timeout'],3)
            value=replies.pop(0)
            if isinstance(value,Exception):raise value
            return subprocess.CompletedProcess(command,0,value,'')
        return out,env,reply
    def test_owned_recovery_verifies_label_and_absence(self):
        out,env,reply=self.run_cleanup([CID,OWNER,'removed',''])
        with patch.object(m.subprocess,'run',side_effect=reply) as commands:m.cleanup_owned_capture(env,out)
        self.assertTrue(json.loads((out/'container-cleanup-recovery.json').read_text())['confirmedAbsent'])
        self.assertEqual(commands.call_args_list[2].args[0],['docker','rm','-f',CID])
    def test_absent_is_confirmed_without_delete(self):
        out,env,reply=self.run_cleanup(['',''])
        with patch.object(m.subprocess,'run',side_effect=reply) as commands:m.cleanup_owned_capture(env,out)
        self.assertEqual(commands.call_count,2)
    def test_wrong_owner_is_never_removed(self):
        out,env,reply=self.run_cleanup([CID,'another-owner'])
        with patch.object(m.subprocess,'run',side_effect=reply) as commands,self.assertRaises(m.Rejected):m.cleanup_owned_capture(env,out)
        self.assertFalse(any('rm' in c.args[0] for c in commands.call_args_list))
        self.assertFalse(json.loads((out/'container-cleanup-recovery.json').read_text())['confirmedAbsent'])
    def test_daemon_failure_is_not_absence(self):
        out,env,reply=self.run_cleanup([subprocess.CalledProcessError(1,['docker','ps'])])
        with patch.object(m.subprocess,'run',side_effect=reply),self.assertRaises(subprocess.CalledProcessError):m.cleanup_owned_capture(env,out)
        self.assertFalse(json.loads((out/'container-cleanup-recovery.json').read_text())['confirmedAbsent'])
    def test_timeout_is_bounded_and_not_absence(self):
        out,env,reply=self.run_cleanup([subprocess.TimeoutExpired(['docker','ps'],3)])
        with patch.object(m.subprocess,'run',side_effect=reply),self.assertRaises(subprocess.TimeoutExpired):m.cleanup_owned_capture(env,out)
        self.assertFalse(json.loads((out/'container-cleanup-recovery.json').read_text())['confirmedAbsent'])
    def test_record_mismatch_refuses_removal(self):
        out,env,reply=self.run_cleanup([CID],record='b'*64)
        with patch.object(m.subprocess,'run',side_effect=reply) as commands,self.assertRaises(m.Rejected):m.cleanup_owned_capture(env,out)
        self.assertEqual(commands.call_count,1)
    def test_podman_keeps_explicit_connection_and_no_record_uses_owned_label(self):
        out,env,reply=self.run_cleanup([CID,OWNER,'removed',''],engine='podman',record=None)
        with patch.object(m.subprocess,'run',side_effect=reply) as commands:m.cleanup_owned_capture(env,out)
        self.assertTrue(all(c.args[0][:3]==['podman','--connection','explicit-test-VM'] for c in commands.call_args_list))
        self.assertEqual(commands.call_args_list[2].args[0][-5:],['rm','-f','--time','0',CID])
    def test_stop_recovers_after_kill_and_closes_log(self):
        capture=m.Capture.__new__(m.Capture);capture.env={};capture.out=Path('/unread');capture.log=io.StringIO();capture.closed=False
        process=Mock();process.poll.return_value=None;process.wait.side_effect=[subprocess.TimeoutExpired(['capture'],3),-9];process.returncode=-9;process.pid=12345;capture.process=process
        with patch.object(m.os,'killpg') as killed,patch.object(m,'cleanup_owned_capture') as cleanup:capture.stop()
        self.assertEqual(killed.call_count,2);self.assertTrue(capture.log.closed);cleanup.assert_called_once_with(capture.env,capture.out)
    def test_shutdown_handlers_restore_originals_after_success(self):
        previous={m.signal.SIGTERM:object(),m.signal.SIGINT:object()};active={}
        with patch.object(m.signal,'getsignal',side_effect=previous.get),patch.object(m.signal,'signal',side_effect=lambda number,handler:active.update({number:handler})):
            with m.shutdown_handlers():
                self.assertTrue(all(callable(active[number]) for number in previous))
            self.assertEqual(active,previous)
    def test_cli_cancellation_unwinds_capture_cleanup_and_restores_handlers(self):
        timeline,captures,clock,reader=Tests.trial(self,mode='hang')
        factory=timeline.capture_factory
        previous={m.signal.SIGTERM:object(),m.signal.SIGINT:object()};active={}
        def capture(*args):
            child=factory(*args);poll=child.poll
            def cancelled_poll():
                if clock.monotonic()-child.start>1:active[m.signal.SIGTERM](m.signal.SIGTERM,None)
                return poll()
            child.poll=cancelled_poll
            return child
        timeline.capture_factory=capture
        with patch.object(m.signal,'getsignal',side_effect=previous.get),patch.object(m.signal,'signal',side_effect=lambda number,handler:active.update({number:handler})):
            with self.assertRaisesRegex(m.Rejected,'interrupted by signal'):
                with m.shutdown_handlers():timeline.run()
        self.assertTrue(captures[0].stopped)
        self.assertEqual(active,previous)
        result=m.read_json(timeline.out/'timeline-results.json')
        self.assertFalse(result['qualifiedDuringLoad']);self.assertIn('interrupted by signal',result['error'])

if __name__=='__main__':unittest.main()
