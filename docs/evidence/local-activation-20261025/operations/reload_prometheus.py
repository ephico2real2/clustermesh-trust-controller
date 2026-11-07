import subprocess,sys,time
from pathlib import Path
c=sys.argv[1];K=['kubectl','--kubeconfig','/private/tmp/cmtc-a-b-20261024.kubeconfig','--context','kind-'+c];want=(Path('/private/tmp/cmtc-primary-operations-20261025')/('monitoring-'+c)/'expected-config-sha256').read_text().strip()
for _ in range(24):
 r=subprocess.run(K+['-n','monitoring','exec','deploy/prometheus','--','sha256sum','/etc/prometheus/prometheus.yml'],capture_output=True,text=True)
 if r.returncode==0 and r.stdout.split()[0]==want:
  subprocess.run(K+['-n','monitoring','exec','deploy/prometheus','--','sh','-c','kill -HUP 1'],check=True)
  print(c,'Prometheus configuration reloaded with existing TSDB preserved',flush=True);break
 time.sleep(5)
else:raise SystemExit('Projected configuration not updated; no reload or storage restart performed')
