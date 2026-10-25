import unittest
from fence_manifest_contract import FenceTemplateError, expected_fence_template, validate_fence_template


class FenceMetricsContractTests(unittest.TestCase):
    def test_discovery_enabled_for_each_profile(self):
        for fanout in (False, True):
            template=expected_fence_template(fanout=fanout)
            validate_fence_template(template,fanout=fanout)
            pod=template['spec']['template']
            self.assertEqual(pod['metadata']['labels']['security.cmtc.io/metrics'],'true')
            c=pod['spec']['containers'][0]
            self.assertEqual(c['ports'],[{'name':'metrics','containerPort':18084,'protocol':'TCP'}])
            self.assertIn('--metrics-listen=$(NODE_IP):18084',c['args'])
            ip=next(e for e in c['env'] if e['name']=='NODE_IP')
            self.assertEqual(ip,{'name':'NODE_IP','valueFrom':{'fieldRef':{'fieldPath':'status.hostIP'}}})

    def test_profile_refuses_wrong_metrics_surface(self):
        for mode in ('wildcard','healthPort','renamedPort','noLabel','wrongIPSource','missingPort'):
            with self.subTest(mode=mode):
                t=expected_fence_template(fanout=True);p=t['spec']['template'];c=p['spec']['containers'][0]
                if mode=='wildcard':c['args'][-1]='--metrics-listen=0.0.0.0:18084'
                if mode=='healthPort':c['ports'][0]['containerPort']=18083
                if mode=='renamedPort':c['ports'][0]['name']='health'
                if mode=='noLabel':p['metadata']['labels'].pop('security.cmtc.io/metrics')
                if mode=='wrongIPSource':next(e for e in c['env'] if e['name']=='NODE_IP')['valueFrom']['fieldRef']['fieldPath']='status.podIP'
                if mode=='missingPort':c.pop('ports')
                with self.assertRaises(FenceTemplateError):validate_fence_template(t,fanout=True)


if __name__=='__main__':unittest.main()
