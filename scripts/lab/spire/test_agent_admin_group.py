#!/usr/bin/env python3
"""Pure tests. No Kubernetes calls or filesystem permission changes."""
import copy
import unittest
import agent_admin_group as p

w=p._workload_api()

UID='aa01ca30-c951-40c2-8055-677c38b2d438'
IMAGE='localhost/spire-agent@sha256:'+'1'*64

def fixture():
    return {'apiVersion':'apps/v1','kind':'DaemonSet','metadata':{'name':'spire-agent','namespace':'cilium-spire','uid':UID,'resourceVersion':'107','labels':{'security.cmtc.io/pki-owner':w.r.OWNER,'security.cmtc.io/pki-cluster':'cmtc-a'}},'spec':{'template':{'metadata':{'annotations':{'security.cmtc.io/workload-api-config':'a'*16}},'spec':{'hostPID':True,'hostNetwork':True,'serviceAccountName':'spire-agent','securityContext':copy.deepcopy(w.r.POD_SECURITY),'containers':[{'name':'spire-agent','image':IMAGE,'volumeMounts':[{'name':'cmtc-node-sockets','mountPath':'/run/spire/sockets/admin','subPath':'admin'},{'name':'cmtc-node-sockets','mountPath':'/run/spire/sockets/agent','subPath':'agent'}]}],'volumes':[{'name':'cmtc-node-sockets','hostPath':{'path':w.BASE+'/cmtc-a','type':'DirectoryOrCreate'}}],'initContainers':[{'name':'prepare-node-sockets','command':['/bin/sh','-ec',w.PREPARE],'securityContext':{'runAsUser':0,'runAsGroup':0,'runAsNonRoot':False,'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL'],'add':['CHOWN']}}}]}}}}

def render(ds,**kwargs):
    options={'cluster':'cmtc-a','expected_uid':UID,'expected_rv':'107','expected_image':IMAGE};options.update(kwargs)
    return p.render(ds,**options)

class Rendering(unittest.TestCase):
    def test_exact_patch_and_unchanged_workload_boundary(self):
        ds=fixture();old=copy.deepcopy(ds);result=render(ds)
        self.assertEqual(ds,old,'renderer mutated input')
        self.assertFalse(result['qualified']);self.assertFalse(result['protectionAvailable'])
        self.assertEqual(result['patch'][:3],[{'op':'test','path':'/metadata/uid','value':UID},{'op':'test','path':'/metadata/resourceVersion','value':'107'},{'op':'test','path':'/spec/template','value':old['spec']['template']}])
        template=result['newTemplate'];pod=template['spec']
        self.assertEqual(pod['securityContext'],w.r.POD_SECURITY)
        self.assertEqual(pod['containers'][0]['securityContext'],{'runAsGroup':1337})
        self.assertEqual(pod['containers'][0]['volumeMounts'],old['spec']['template']['spec']['containers'][0]['volumeMounts'])
        self.assertEqual(pod['initContainers'][0]['command'],['/bin/sh','-ec',p.PREPARE])
        init=pod['initContainers'][1]
        self.assertEqual(init['securityContext']['capabilities'],{'drop':['ALL']})
        self.assertEqual((init['securityContext']['runAsUser'],init['securityContext']['runAsGroup']),(1000,1337))
        self.assertEqual(init['command'],['/bin/sh','-ec',p.MIGRATE])
        self.assertEqual(pod['volumes'],old['spec']['template']['spec']['volumes'])
    def test_independent_identity_image_and_rv_pins(self):
        for options in ({'cluster':'foreign'},{'expected_uid':'00000000-0000-0000-0000-000000000000'},{'expected_uid':UID.upper()},{'expected_rv':'108'},{'expected_image':'agent:latest'},{'expected_image':IMAGE[:-1]+'2'}):
            with self.subTest(options=options),self.assertRaises(ValueError):render(fixture(),**options)
    def test_unreviewed_privilege_mount_or_incarnation_refused(self):
        changes=[lambda d:d['metadata'].update(deletionTimestamp='now'),lambda d:d['metadata']['labels'].update({'security.cmtc.io/pki-owner':'foreign'}),lambda d:d['spec']['template']['metadata']['annotations'].clear(),lambda d:d['spec']['template']['spec'].update(hostPID=False),lambda d:d['spec']['template']['spec']['securityContext'].update(fsGroup=1337),lambda d:d['spec']['template']['spec']['containers'][0].update(securityContext={'capabilities':{'add':['DAC_OVERRIDE']}}),lambda d:d['spec']['template']['spec']['volumes'][0]['hostPath'].update(path='/run/foreign'),lambda d:d['spec']['template']['spec']['containers'][0]['volumeMounts'][0].update(subPath='agent'),lambda d:d['spec']['template']['spec']['initContainers'][0].update(command=['/bin/sh','-ec','chmod -R 777 /'])]
        for change in changes:
            ds=fixture();change(ds)
            with self.subTest(change=change),self.assertRaises(ValueError):render(ds)
    def test_rendered_profile_cannot_be_applied_twice_silently(self):
        ds=fixture();ds['spec']['template']=render(ds)['newTemplate']
        with self.assertRaises(ValueError):render(ds)

if __name__=='__main__':unittest.main()
