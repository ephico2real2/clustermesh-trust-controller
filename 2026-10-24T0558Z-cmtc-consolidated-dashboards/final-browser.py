import json,pathlib,subprocess
root=pathlib.Path('/private/tmp/cmtc-dashboard-redesign');r=json.loads((root/'final-range.json').read_text())
cmd=['docker','run','--rm','--init','--network','host','--shm-size=1g','--env','S=/captures','--env','CMTC_GRAFANA_URL=http://127.0.0.1:13000','--env','CMTC_REQUIRE_NATIVE_MTLS=true','--env','CMTC_CAPTURE_FROM_MS='+str(r['fromMilliseconds']),'--env','CMTC_CAPTURE_TO_MS='+str(r['toMilliseconds']),'--volume','/private/tmp/cmtc-operations-capture.mjs:/opt/cmtc-capture/capture.mjs:ro','--volume',str(root/'final-screenshots')+':/captures','cmtc-capture:dev']
subprocess.run(cmd,check=True)
subprocess.run(['docker','run','--rm','--init','--network','host','--shm-size=1g','--volume',str(root/'layout-check.cjs')+':/opt/cmtc-capture/layout-check.cjs:ro','--volume',str(root/'final-screenshots')+':/captures','--entrypoint','node','cmtc-capture:dev','/opt/cmtc-capture/layout-check.cjs'],check=True)
