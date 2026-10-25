#!/usr/bin/env python3
"""Opt-in, real-API publication-only lab. It NEVER qualifies TLS/Protected.
Run only after independent source/image review. See README.md for side effects.
"""
from __future__ import annotations
import argparse, copy, datetime as dt, hashlib, json, os, re, subprocess, sys, time, urllib.parse, urllib.request, uuid
from pathlib import Path

OWNER = "security.cmtc.io/issuer-profile-lab-run"
OUTPUT = "security.cmtc.io/issuer-profile-output"
INIT = "security.cmtc.io/issuer-profile-initialized"
NS = "cmtc-system"
DEP = "cmtc-controller"
METRICS = ["cmtc_issuer_profile_validation_attempts_total", "cmtc_issuer_profile_publication_writes_total", "cmtc_issuer_profile_source_checked_timestamp_seconds", "cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds"]
class Refusal(RuntimeError): pass
PUBLICATION_LIMIT = 256 * 1024
APPROVAL_LIMIT = 64 * 1024

def require_running_manifest(running, repo_digests):
    digest = running.split("://", 1)[-1].rsplit("@", 1)[-1]
    accepted = {ref.rsplit("@", 1)[-1] for ref in repo_digests}
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or digest not in accepted:
        raise Refusal("running manifest digest not in actual CRI image")
    return digest


def compact(x):
    # Go encoding/json struct order is retained from the actual output wire bytes.
    return json.dumps(x, ensure_ascii=False, separators=(",", ":")).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
def sha(x): return hashlib.sha256(x.encode()).hexdigest()
def stamp(x): return dt.datetime.fromisoformat(x.replace("Z", "+00:00")).timestamp()
def unique_object(pairs):
    d = {}
    for k, v in pairs:
        if k in d: raise Refusal("duplicate JSON key: " + k)
        d[k] = v
    return d

def publication(raw, cluster, uid, now=None):
    if not isinstance(raw, str) or not 0 < len(raw.encode()) <= PUBLICATION_LIMIT: raise Refusal("publication byte budget")
    p = json.loads(raw, object_pairs_hook=unique_object)
    keys = {"schemaVersion", "sequence", "state", "reason", "producerCluster", "outputUID", "expectedSourceUID", "source", "acceptedGeneration", "acceptedSourceUID", "acceptedApprovalDigest", "approvalDigest", "approval", "publishedAt", "validUntil", "digest"}
    if set(p) - keys or p.get("schemaVersion") != 1 or type(p.get("sequence")) is not int or p["sequence"] < 1: raise Refusal("publication schema")
    if p.get("producerCluster") != cluster or p.get("outputUID") != uid: raise Refusal("publication provenance")
    d = p.pop("digest", None)
    if not re.fullmatch("[0-9a-f]{64}", d or "") or sha(compact(p)) != d: raise Refusal("publication canonical digest")
    p["digest"] = d
    if p["state"] == "published":
        if "approval" not in p or len(compact(p["approval"]).encode()) > APPROVAL_LIMIT or sha(compact(p["approval"])) != p.get("approvalDigest"): raise Refusal("approval digest")
        if p["acceptedApprovalDigest"] != p["approvalDigest"] or p["acceptedSourceUID"] != p["source"]["uid"]: raise Refusal("accepted source provenance")
        now = time.time() if now is None else now
        if not stamp(p["publishedAt"]) <= now < stamp(p["validUntil"]) <= stamp(p["publishedAt"]) + 30: raise Refusal("published lease not current/bounded")
    elif p["state"] == "withdrawn":
        if "approval" in p or "approvalDigest" in p or stamp(p["validUntil"]) != stamp(p["publishedAt"]): raise Refusal("tombstone must contain no active mapping")
    else: raise Refusal("publication state")
    return p

def owned(obj, run, uid=None):
    m = obj.get("metadata", {})
    if m.get("labels", {}).get(OWNER) != run or not m.get("uid") or not m.get("resourceVersion") or (uid and m["uid"] != uid) or m.get("deletionTimestamp"): raise Refusal("object ownership/UID/RV/deletion mismatch")
    return obj

def tests_for(obj):
    return [{"op": "test", "path": "/metadata/uid", "value": obj["metadata"]["uid"]}, {"op": "test", "path": "/metadata/resourceVersion", "value": obj["metadata"]["resourceVersion"]}]

def check_source(cm, run, uid):
    owned(cm, run, uid)
    if cm.get("immutable") is not True or set(cm.get("data", {})) != {"approval.json"} or cm.get("binaryData"): raise Refusal("source immutable/exact data contract")

def fixture_variation(base, variant, generation):
    x = copy.deepcopy(base["approvals"][variant]); x["generation"] = generation
    return compact(x)

class Runner:
    def __init__(self, out): self.out = out; self.index = 0; self.followers = []
    def run(self, argv, data=None, check=True, timeout=35):
        for _, stream in self.followers:
            if Path(stream.name).stat().st_size > 10_000_000: raise Refusal("owned controller log exceeds 10MB")
        self.index += 1; name = f"{self.index:05d}"; start = time.time()
        try:
            p = subprocess.run(argv, input=None if data is None else compact(data), text=True, capture_output=True, timeout=timeout)
            stdout, stderr, code = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as e:
            stdout, stderr, code = e.stdout or "", e.stderr or "", -999
            if isinstance(stdout, bytes): stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes): stderr = stderr.decode(errors="replace")
        for suffix, value in [("stdout", stdout), ("stderr", stderr)]:
            # Public API material only. Never invoke token/Secret/private-key commands.
            (self.out / f"{name}.{suffix}").write_text(value[:2_000_000])
        (self.out / f"{name}.json").write_text(json.dumps({"argv": argv, "started": start, "elapsed": time.time()-start, "exit": code, "stdoutFile": name+".stdout", "stderrFile": name+".stderr"}, indent=2))
        if check and code: raise Refusal(f"command failed ({code}), see {name}: {stderr[-1000:]}")
        return code, stdout, stderr
    def follow(self, argv, name):
        f = open(self.out / name, "w"); p = subprocess.Popen(argv, stdout=f, stderr=subprocess.STDOUT, text=True)
        self.followers.append((p, f)); return p
    def stop(self):
        for p, f in self.followers:
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=5)
                except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
            f.close()
        self.followers = []

class Lab:
    def __init__(self, args, cluster, fixtures, out):
        self.a, self.cluster, self.fx, self.out = args, cluster, fixtures, out
        self.runid = uuid.uuid4().hex[:12]; self.r = Runner(out); self.owned = {}; self.events = []; self.fatal = None; self.snapshot = None; self.expected_template = None; self.last = None; self.pod_seen = set(); self.taken = False; self.active_source_uid = None
        self.names = {k: "issuer-lab-"+k+"-"+self.runid for k in ["source", "output", "cas", "access"]}
        self.kbase = ["kubectl", "--kubeconfig", args.kubeconfig, "--context", "kind-"+cluster, "--request-timeout=12s", "-n", NS]
        self.prom = args.prometheus_a if cluster == "cmtc-a" else args.prometheus_b
    def save(self):
        obj = {"cluster": self.cluster, "run": self.runid, "scope": "admin-approved issuer mapping publication only; no TLS, authorization or Protected qualification", "events": self.events, "owned": {f"{k[0]}/{k[1]}":v for k,v in self.owned.items()}, "failure": self.fatal}
        p = self.out / "report.json.tmp"; p.write_text(json.dumps(obj, indent=2)); p.replace(self.out / "report.json")
    def event(self, stage, **values): self.events.append({"stage":stage,"at":time.time(),**values}); self.save()
    def k(self, *args, data=None, check=True): return self.r.run(self.kbase + list(args), data, check)
    def get(self, kind, name, absent=False):
        code, text, err = self.k("get", kind, name, "-o", "json", check=False)
        if code:
            if absent and "(NotFound)" in err: return None
            raise Refusal("API get failed: " + err[-1000:])
        return json.loads(text)
    def wait(self, fn, label, timeout=100):
        deadline=time.monotonic()+timeout; last=None
        while time.monotonic()<deadline:
            try:
                result=fn()
                if result: return result
            except (Refusal, KeyError, ValueError) as e: last=str(e)
            time.sleep(1)
        raise Refusal(f"timeout: {label}; last={last}")
    def create(self, obj):
        kind,name=obj["kind"],obj["metadata"]["name"]
        if self.get(kind,name,absent=True) is not None: raise Refusal("refusing preexisting " + kind+"/"+name)
        obj["metadata"]["labels"]={**obj["metadata"].get("labels",{}),OWNER:self.runid};obj["metadata"]["namespace"]=NS
        code,raw,err=self.k("create","-f","-","-o","json",data=obj,check=False)
        if code:
            observed=self.get(kind,name,absent=True)
            if observed is not None:
                observed=owned(observed,self.runid)
                self.owned[(kind,name)]=observed["metadata"]["uid"];self.save()
            raise Refusal("create response not acknowledged; task-owned result retained for cleanup: "+err[-500:])
        result=owned(json.loads(raw),self.runid);self.owned[(kind,name)]=result["metadata"]["uid"];self.save();return result
    def patch_owned(self, kind, name, changes):
        obj=owned(self.get(kind,name),self.runid,self.owned[(kind,name)])
        _,raw,_=self.k("patch",kind,name,"--type=json","-p",compact(tests_for(obj)+changes),"-o","json")
        return owned(json.loads(raw),self.runid,obj["metadata"]["uid"])
    def delete_owned(self,kind,name):
        expected=self.owned.get((kind,name));obj=self.get(kind,name,absent=True)
        if obj is None: return
        owned(obj,self.runid,expected)
        routes={"ConfigMap":"/api/v1","Role":"/apis/rbac.authorization.k8s.io/v1","RoleBinding":"/apis/rbac.authorization.k8s.io/v1"}
        plural={"ConfigMap":"configmaps","Role":"roles","RoleBinding":"rolebindings"}
        body={"apiVersion":"v1","kind":"DeleteOptions","propagationPolicy":"Foreground","preconditions":{"uid":expected,"resourceVersion":obj["metadata"]["resourceVersion"]}}
        self.k("delete","--raw",routes[kind]+"/namespaces/"+NS+"/"+plural[kind]+"/"+name,"-f","-",data=body)
        def gone():
            x=self.get(kind,name,absent=True)
            if x is None:return True
            if x["metadata"]["uid"]!=expected:raise Refusal("replacement object encountered during cleanup")
            return False
        self.wait(gone,"delete "+name)
        del self.owned[(kind,name)];self.save()
    def node(self,node,*cmd):
        return self.r.run(["colima","ssh","--profile",self.a.colima_profile,"--","docker","exec",node]+list(cmd))
    def inspect_image(self,node):
        _,raw,_=self.node(node,"crictl","inspecti",self.a.image);img=json.loads(raw)
        spec=img.get("info",{}).get("imageSpec",{});status=img["status"]
        if status["id"]!=self.a.image_id or spec.get("architecture")!="arm64" or spec.get("config",{}).get("Labels",{}).get("org.opencontainers.image.revision")!=self.a.source_sha:raise Refusal("actual CRI source/config/architecture differs")
        self.event("image-inspected",node=node,imageConfig=status["id"],architecture=spec["architecture"],sourceRevision=self.a.source_sha,repoDigests=status.get("repoDigests",[]))
        return status
    def preflight(self):
        for node in [self.cluster+"-worker",self.cluster+"-control-plane"]:self.inspect_image(node)
        d=self.get("deployment",DEP);s=d["spec"];self.sa=self.get("serviceaccount","cmtc-controller")
        if s.get("replicas",1)!=1 or s["template"]["spec"].get("serviceAccountName")!="cmtc-controller":raise Refusal("unexpected existing controller topology")
        if OWNER in d["metadata"].get("annotations",{}) or OWNER in s["template"]["metadata"].get("annotations",{}):raise Refusal("existing lab owner")
        cs=s["template"]["spec"]["containers"]
        if len(cs)!=1 or cs[0]["name"]!="controller" or any(x.startswith("--issuer-profile") for x in cs[0].get("args",[])):raise Refusal("existing producer/containers; refusing takeover")
        if "--cluster-name="+self.cluster not in cs[0].get("args",[]):raise Refusal("existing cluster name differs")
        self.snapshot=copy.deepcopy(d);self.expected_template=copy.deepcopy(s["template"])
        (self.out/"deployment-before.json").write_text(json.dumps(d,indent=2))
        self.event("preflight",deploymentUID=d["metadata"]["uid"],serviceAccountUID=self.sa["metadata"]["uid"])
    def rollout(self, flags=None, restoring=False):
        d=self.get("deployment",DEP)
        if d["metadata"]["uid"]!=self.snapshot["metadata"]["uid"] or d["spec"]["template"]!=self.expected_template:raise Refusal("Deployment foreign drift; preserving current state")
        owner=d["metadata"].get("annotations",{}).get(OWNER)
        if owner != (self.runid if self.taken else None):raise Refusal("Deployment owner changed")
        template=copy.deepcopy(self.snapshot["spec"]["template"])
        annotations=dict(d["metadata"].get("annotations",{}))
        if restoring:
            annotations.pop(OWNER,None)
        else:
            template["metadata"].setdefault("annotations",{})[OWNER]=self.runid
            template["metadata"]["annotations"]["security.cmtc.io/issuer-lab-restart"]=str(uuid.uuid4())
            c=template["spec"]["containers"][0];c["image"]=self.a.image;c["imagePullPolicy"]="Never";c["args"]=list(c.get("args",[]))+(flags or [])
            annotations[OWNER]=self.runid
        ops=tests_for(d)+[{"op":"test","path":"/spec/template","value":self.expected_template},{"op":"add","path":"/metadata/annotations","value":annotations},{"op":"replace","path":"/spec/template","value":template}]
        self.k("patch","deployment",DEP,"--type=json","-p",compact(ops))
        self.expected_template=template # Keep expected ownership even if rollout fails.
        self.taken = not restoring
        self.active_source_uid = next((f.split("=",1)[1] for f in (flags or []) if f.startswith("--issuer-profile-source-uid=")),None)
        self.r.run(self.kbase+["--request-timeout=170s","rollout","status","deployment/"+DEP,"--timeout=150s"],timeout=180)
        def current():
            dep=self.get("deployment",DEP)
            if dep["metadata"]["uid"]!=d["metadata"]["uid"] or dep["spec"]["template"]!=template:raise Refusal("Deployment drift after rollout")
            _,raw,_=self.k("get","pods","-l","app.kubernetes.io/name=cmtc-controller","-o","json")
            pods=[]
            for p in json.loads(raw)["items"]:
                if p["metadata"].get("deletionTimestamp"):continue
                refs=p["metadata"].get("ownerReferences",[])
                if len(refs)!=1 or refs[0]["kind"]!="ReplicaSet":continue
                rs=self.get("replicaset",refs[0]["name"])
                if rs["metadata"]["uid"]!=refs[0]["uid"] or not any(x.get("uid")==d["metadata"]["uid"] and x.get("kind")=="Deployment" for x in rs["metadata"].get("ownerReferences",[])):continue
                if p["spec"]["containers"][0]["image"]==template["spec"]["containers"][0]["image"] and p["metadata"].get("annotations",{}).get("security.cmtc.io/issuer-lab-restart")==template["metadata"].get("annotations",{}).get("security.cmtc.io/issuer-lab-restart"):pods.append(p)
            if len(pods)!=1:return None
            p=pods[0];st=p.get("status",{}).get("containerStatuses",[])
            if not st or not all(x.get("ready") for x in st) or not p.get("status",{}).get("podIP"):return None
            return p
        p=self.wait(current,"exact controller rollout",timeout=90);self.pod=p
        if not restoring:
            status=self.inspect_image(p["spec"]["nodeName"]);cs=p["status"]["containerStatuses"][0]
            running=cs["imageID"].split("://",1)[-1]
            require_running_manifest(running, status.get("repoDigests", []))
            cid=cs["containerID"].split("://",1)[-1]
            _,raw,_=self.node(p["spec"]["nodeName"],"crictl","inspect",cid);pid=json.loads(raw).get("info",{}).get("pid")
            if type(pid) is not int or pid<2:raise Refusal("missing actual controller PID")
            _,binary,_=self.node(p["spec"]["nodeName"],"sha256sum",f"/proc/{pid}/root/cmtc")
            if binary.split()[0]!=self.a.binary_sha256:raise Refusal("actual running binary hash differs from build ledger")
            self.event("running-image-verified",podUID=p["metadata"]["uid"],node=p["spec"]["nodeName"],imageID=cs["imageID"],configID=status["id"],sourceRevision=self.a.source_sha,binarySHA256=binary.split()[0])
            if p["metadata"]["uid"] not in self.pod_seen:
                self.pod_seen.add(p["metadata"]["uid"])
                self.r.follow(self.kbase+["--request-timeout=0","logs","-f",p["metadata"]["name"],"-c","controller","--timestamps"],"controller-"+p["metadata"]["uid"]+".log")
        self.event("rollout",restored=restoring,podUID=p["metadata"]["uid"])
        return p
    def cm(self,name,data,immutable=False,output=False):
        return self.create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":name,"labels":{OUTPUT:"true"} if output else {}},"immutable":immutable,"data":data})
    def source(self,variant,generation):
        name=self.names["source"]
        if ("ConfigMap",name) in self.owned:self.delete_owned("ConfigMap",name)
        self.source_cm=self.cm(name,{"approval.json":fixture_variation(self.fx,variant,generation)},True)
        self.generation=generation;self.variant=variant;return self.source_cm
    def options(self,min_generation=None):
        return ["--issuer-profile-producer=true","--issuer-profile-namespace="+NS,"--issuer-profile-source="+self.names["source"],"--issuer-profile-output="+self.names["output"],"--issuer-profile-source-uid="+self.source_cm["metadata"]["uid"],"--issuer-profile-output-uid="+self.output_cm["metadata"]["uid"],"--issuer-profile-root-sha256="+self.fx["rootPin"],"--issuer-profile-minimum-generation="+str(min_generation or self.generation)]
    def rbac(self):
        access=self.names["access"]
        for verb,res in [("get","configmap/"+self.names["source"]),("get","configmap/"+self.names["output"]),("update","configmap/"+self.names["output"]),("list","configmaps"),("get","secret/issuer-lab-never-created")]:
            _,text,err=self.k("auth","can-i",verb,res,"--as=system:serviceaccount:"+NS+":cmtc-controller","--as-group=system:serviceaccounts","--as-group=system:serviceaccounts:"+NS,"--as-group=system:authenticated",check=False)
            if text.strip()!="no":raise Refusal("unexpected baseline privilege: "+verb+" "+res+": "+text+err)
            self.event("rbac-baseline",verb=verb,resource=res,allowed=False)
        self.create({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":access},"rules":[{"apiGroups":[""],"resources":["configmaps"],"resourceNames":[self.names["source"]],"verbs":["get"]},{"apiGroups":[""],"resources":["configmaps"],"resourceNames":[self.names["output"]],"verbs":["get","update"]}]})
        self.create({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":access},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":access},"subjects":[{"kind":"ServiceAccount","name":"cmtc-controller","namespace":NS}]})
        for verb,res,want in [("get","configmap/"+self.names["source"],True),("get","configmap/"+self.names["output"],True),("update","configmap/"+self.names["output"],True),("update","configmap/"+self.names["source"],False),("update","configmap/"+self.names["cas"],False),("list","configmaps",False),("watch","configmaps",False),("create","configmaps",False),("delete","configmap/"+self.names["output"],False),("get","secret/issuer-lab-never-created",False),("list","secrets",False),("watch","secrets",False)]:
            code,text,err=self.k("auth","can-i",verb,res,"--as=system:serviceaccount:"+NS+":cmtc-controller","--as-group=system:serviceaccounts","--as-group=system:serviceaccounts:"+NS,"--as-group=system:authenticated",check=False)
            got=text.strip()=="yes"
            if got!=want or (not want and text.strip()!="no"):raise Refusal("unexpected existing/effective SA permission "+verb+" "+res+": "+text+err)
            self.event("rbac",verb=verb,resource=res,allowed=got)
    def readpub(self):
        cm=owned(self.get("ConfigMap",self.names["output"]),self.runid,self.output_cm["metadata"]["uid"])
        p=publication(cm.get("data",{}).get("profile.json",""),self.cluster,cm["metadata"]["uid"])
        return cm,p
    def expect(self,state,reason=None,generation=None):
        def matches():
            cm,p=self.readpub()
            if p["state"]!=state or (reason and p["reason"]!=reason) or (generation is not None and p["acceptedGeneration"]!=generation):return None
            if p["expectedSourceUID"]!=self.active_source_uid:return None
            return cm,p
        cm,p=self.wait(matches,"publication "+state+" "+str(reason),timeout=110)
        if p["expectedSourceUID"] != self.active_source_uid:raise Refusal("publication expected source UID differs from active Deployment approval")
        if p["state"] == "published":
            source=owned(self.get("ConfigMap",self.names["source"]),self.runid,self.source_cm["metadata"]["uid"])
            want={"namespace":NS,"name":self.names["source"],"uid":source["metadata"]["uid"],"resourceVersion":source["metadata"]["resourceVersion"],"generation":self.generation}
            if p["source"]!=want or p["acceptedGeneration"]!=self.generation or p["approval"]!=json.loads(source["data"]["approval.json"]):raise Refusal("published source UID/RV/generation/content mismatch")
        self.last=p;self.event("publication",body=p,bytesSHA256=sha(cm["data"]["profile.json"]),resourceVersion=cm["metadata"]["resourceVersion"])
        return cm,p
    def prom_query(self,q):
        url=self.prom.rstrip("/")+"/api/v1/query?"+urllib.parse.urlencode({"query":q})
        with urllib.request.urlopen(url,timeout=12) as response:obj=json.load(response)
        if obj.get("status")!="success" or obj["data"]["resultType"]!="vector":raise Refusal("Prometheus query failed")
        self.event("query",query=q,response=obj)
        return obj["data"]["result"]
    def selector(self):return '{job="cmtc",component="cmtc-controller",cluster="'+self.cluster+'",instance="'+self.pod["status"]["podIP"]+':8080"}'
    def metrics(self,active=True,withdrawn=False,source_present=True):
        s=self.selector()
        if not active:
            def observed_disabled():
                rows=self.prom_query('cmtc_enforcement_available'+s)
                if not rows:return False
                if any(float(x["value"][1])!=0 for x in rows):raise Refusal("Observe advertises enforcement")
                stamps=self.prom_query('timestamp(cmtc_enforcement_available'+s+')')
                if len(stamps)!=len(rows) or any(not 0 <= time.time()-float(x["value"][1]) < 20 for x in stamps):return False
                return all(not self.prom_query(m+s) for m in METRICS)
            self.wait(observed_disabled,"fresh Observe scrape with disabled producer metrics absent",timeout=50)
            self.event("observe-smoke",enforcementAvailable=False);return
        def ready():
            rows={m:self.prom_query(m+s) for m in METRICS}
            if any(not x for x in rows.values()):return None
            for m,series in rows.items():
                for x in series:
                    labels=x["metric"]
                    if set(labels)-{"__name__","cluster","component","instance","job","node","exported_cluster","result","state"}:raise Refusal("unexpected/unbounded producer metric labels")
                    if labels.get("exported_cluster",self.cluster)!=self.cluster:raise Refusal("exporter cluster mismatch")
                    if "result" in labels and labels["result"] not in {"accepted","rejected","unavailable","acknowledged","error"}:raise Refusal("metric enum")
                    if "state" in labels and labels["state"] not in {"published","withdrawn"}:raise Refusal("metric enum")
            for m in METRICS:
                timestamps = self.prom_query("timestamp(" + m + s + ")")
                if len(timestamps) != len(rows[m]) or any(not 0 <= time.time() - float(x["value"][1]) < 20 for x in timestamps):
                    return None
            checked = float(rows[METRICS[2]][0]["value"][1])
            if source_present:
                if not 0 <= time.time() - checked < 20: return None
            elif not 0 <= checked <= time.time():
                raise Refusal("missing source has an invalid historical checked timestamp")
            until=float(rows[METRICS[3]][0]["value"][1])
            if (withdrawn and until!=0) or (not withdrawn and until<=time.time()):return None
            return rows
        rows=self.wait(ready,"four actual producer scrape families",timeout=65)
        # Targets are checked on each local Prometheus, not inferred from A's B remote-write series.
        with urllib.request.urlopen(self.prom.rstrip("/")+"/api/v1/targets",timeout=12) as response:targets=json.load(response)
        found=[t for t in targets["data"]["activeTargets"] if t["labels"].get("instance")==self.pod["status"]["podIP"]+":8080" and t["labels"].get("job")=="cmtc"]
        if len(found)!=1 or found[0].get("health")!="up":raise Refusal("actual current local Prom target not UP")
        self.event("scrape",families=rows,target=found[0],semantics="process attempt/ack counters; lease gauges, not trust consumption or protection")
        return rows
    def immutable_and_cas(self):
        src=self.source_cm
        code,_,err=self.k("patch","ConfigMap",self.names["source"],"--type=json","-p",compact(tests_for(src)+[{"op":"replace","path":"/data/approval.json","value":"{}"}]),check=False)
        if code==0 or "immutable" not in err.lower():raise Refusal("API did not reject immutable source mutation")
        check_source(self.get("ConfigMap",self.names["source"]),self.runid,src["metadata"]["uid"])
        old=self.cm(self.names["cas"],{"v":"1"});self.patch_owned("ConfigMap",self.names["cas"],[{"op":"replace","path":"/data/v","value":"2"}])
        old["data"]["v"]="stale"
        code,_,err=self.k("replace","-f","-",data=old,check=False)
        if code==0 or "Conflict" not in err:raise Refusal("real stale-RV update not rejected")
        if self.get("ConfigMap",self.names["cas"])["data"]["v"]!="2":raise Refusal("stale update changed output")
        self.event("api-immutability-and-cas",passed=True)
    def idempotence_renewal(self):
        cm,p=self.wait(lambda:self.freshpub(),"fresh lease",timeout=65)
        before_metrics=self.metrics();before_rv=cm["metadata"]["resourceVersion"];beforeseq=p["sequence"]
        # Prom collection may take >15 seconds. Select a fresh publication again immediately before idle interval.
        cm,p=self.wait(lambda:self.freshpub(),"fresh lease after scrape",timeout=65);before_rv=cm["metadata"]["resourceVersion"];beforeseq=p["sequence"]
        time.sleep(6);after,ap=self.readpub()
        if after["metadata"]["resourceVersion"]!=before_rv or ap["sequence"]!=beforeseq:raise Refusal("idempotent source churned before renewal threshold")
        self.event("idempotent",resourceVersion=before_rv,sequence=beforeseq,waitSeconds=6)
        cm,np=self.wait(lambda:self.renewed(beforeseq),"lease renewed",timeout=45)
        if np["acceptedGeneration"]!=p["acceptedGeneration"] or np["acceptedApprovalDigest"]!=p["acceptedApprovalDigest"] or np["acceptedSourceUID"]!=p["acceptedSourceUID"]:raise Refusal("renewal changed approval identity")
        self.last=np;self.event("lease-renewed",beforeSequence=beforeseq,afterSequence=np["sequence"])
    def freshpub(self):
        cm,p=self.readpub();return (cm,p) if p["state"]=="published" and stamp(p["validUntil"])-time.time()>25 else None
    def renewed(self,seq):
        cm,p=self.readpub();return (cm,p) if p["state"]=="published" and p["sequence"]>seq else None
    def logs(self):
        self.r.stop();records=[]
        for path in self.out.glob("controller-*.log"):
            if path.stat().st_size>10_000_000:raise Refusal("controller log output exceeded bound")
            for line in path.read_text().splitlines():
                start=line.find("{")
                if start<0:continue
                try:o=json.loads(line[start:])
                except ValueError:continue
                if o.get("component")=="issuer-profile-producer":records.append(o)
        for stage in ["validate","publish","output-read","reconcile"]:
            rs=[x for x in records if x.get("stage")==stage and x.get("enforcementAvailable") is False and isinstance(x.get("attempt"),int) and x["attempt"]>0 and "elapsed" in x and "deadline" in x and ("nextRetry" in x or "backoff" in x)]
            if not rs:raise Refusal("missing actual structured boundary log: "+stage)
        if not any(x.get("state")=="withdrawn" and x.get("stage")=="publish" for x in records):raise Refusal("missing actual withdrawal acknowledgment log")
        self.event("structured-logs",records=len(records),stages=["validate","publish","output-read","reconcile"])
    def execute(self):
        try:
            self.preflight();self.rollout();self.metrics(active=False)
            self.source("valid",1);self.output_cm=self.cm(self.names["output"],{},output=True);self.rbac();self.immutable_and_cas()
            self.rollout(self.options());self.expect("published","Validated",1);self.idempotence_renewal()
            old=self.last;self.rollout(self.options());_,p=self.expect("published","Validated",1)
            if p["sequence"]<old["sequence"]:raise Refusal("restart lost durable sequence floor")
            self.metrics()
            self.delete_owned("ConfigMap",self.names["source"]);self.expect("withdrawn","SourceDeleted",1);self.metrics(withdrawn=True,source_present=False)
            self.source("valid",1);self.expect("withdrawn","SourceUIDMismatch",1)
            self.rollout(self.options());self.expect("withdrawn","GenerationRollback",1)
            generation=2
            self.source("valid",generation);self.rollout(self.options(min_generation=generation+1));self.expect("withdrawn","GenerationRollback",1)
            self.rollout(self.options());self.expect("published","Validated",generation)
            for variant in ["wrong-root","duplicate-key","expired"]:
                generation+=1;self.source(variant,generation);self.rollout(self.options());_,bad=self.expect("withdrawn",generation=generation-1)
                if bad["reason"] in {"Validated","SourceUIDMismatch","SourceDeleted","GenerationRollback"}:raise Refusal("invalid fixture did not reach certificate/approval validation")
                self.metrics(withdrawn=True)
                generation+=1;self.source("valid",generation);self.rollout(self.options());self.expect("published","Validated",generation)
            # Corruption: capture the exact RV/body which the conditional patch is based on.
            cm,p=self.readpub();saved=cm["data"]["profile.json"]
            self.k("patch","ConfigMap",self.names["output"],"--type=json","-p",compact(tests_for(cm)+[{"op":"replace","path":"/data/profile.json","value":"{corrupt-public-fixture"}]))
            corrupt=self.get("ConfigMap",self.names["output"]);time.sleep(12)
            after=owned(self.get("ConfigMap",self.names["output"]),self.runid,cm["metadata"]["uid"])
            if after["data"]!=corrupt["data"] or after["metadata"]["resourceVersion"]!=corrupt["metadata"]["resourceVersion"]:raise Refusal("producer overwrote corrupt output")
            self.patch_owned("ConfigMap",self.names["output"],[{"op":"replace","path":"/data/profile.json","value":saved}]);self.expect("published","Validated",generation)
            self.event("corrupt-output-preserved-and-admin-repaired",sequence=p["sequence"])
            self.delete_owned("ConfigMap",self.names["output"]);time.sleep(12)
            if self.get("ConfigMap",self.names["output"],absent=True) is not None:raise Refusal("producer recreated missing output")
            self.output_cm=self.cm(self.names["output"],{},output=True);time.sleep(12)
            empty=owned(self.get("ConfigMap",self.names["output"]),self.runid,self.output_cm["metadata"]["uid"])
            if empty.get("data"):raise Refusal("producer wrote replacement output without configured UID approval")
            generation+=1;self.source("valid",generation);self.rollout(self.options());self.expect("published","Validated",generation);self.metrics()
            self.event("missing-output-preserved-admin-recovery",minimumGeneration=generation,outputUID=self.output_cm["metadata"]["uid"])
            self.logs();self.event("qualification-cases-passed",noTrafficProtectionClaim=True)
        except BaseException as e:
            self.fatal=f"{type(e).__name__}: {e}";self.save();raise
        finally:
            self.r.stop();restored=False
            try:
                if self.snapshot is not None:
                    self.rollout(restoring=True);self.metrics(active=False)
                    if self.get("serviceaccount","cmtc-controller")["metadata"]["uid"]!=self.sa["metadata"]["uid"]:raise Refusal("controller SA replaced")
                    restored=True
                else:restored=True
                # Restore first: never remove RBAC/config while a producer remains enabled.
                for kind,name in list(reversed(self.owned)):self.delete_owned(kind,name)
                self.event("cleanup",controllerTemplateRestored=restored,taskResourcesRemaining=len(self.owned))
            except BaseException as cleanup_error:
                self.event("cleanup-failed",error=str(cleanup_error),controllerRestored=restored,retainedAuthority=not restored)
                if self.fatal is None:self.fatal="cleanup: "+str(cleanup_error)
            self.save()
        if self.fatal:raise Refusal(self.fatal)

def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",required=True);p.add_argument("--image-id",required=True);p.add_argument("--source-sha",required=True);p.add_argument("--binary-sha256",required=True)
    p.add_argument("--fixtures",required=True,type=Path);p.add_argument("--out",required=True,type=Path)
    p.add_argument("--kubeconfig",default="/private/tmp/cmtc-a-b-20261024.kubeconfig");p.add_argument("--colima-profile",default="cmtc-cilium")
    p.add_argument("--prometheus-a",default="http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom");p.add_argument("--prometheus-b",default="http://127.0.0.1:19091")
    p.add_argument("--cluster",choices=["both","cmtc-a","cmtc-b"],default="both")
    return p

def main():
    a=parser().parse_args()
    if not re.fullmatch("[0-9a-f]{40}",a.source_sha) or not re.fullmatch("sha256:[0-9a-f]{64}",a.image_id) or not re.fullmatch("[0-9a-f]{64}",a.binary_sha256):raise Refusal("full source/config/binary digests required")
    if not a.image.startswith("localhost/cmtc:") or "@" in a.image or not re.fullmatch(r"localhost/cmtc:[A-Za-z0-9_.-]+",a.image):raise Refusal("explicit local CMTC image required")
    if a.out.exists():raise Refusal("fresh evidence directory required")
    a.out.mkdir(parents=True,mode=0o700)
    raw=a.fixtures.read_text()
    if len(raw)>200000 or "PRIVATE KEY" in raw:raise Refusal("public-only fixture bundle required")
    fixtures=json.loads(raw,object_pairs_hook=unique_object)
    if set(fixtures)!={"rootPin","approvals"} or set(fixtures["approvals"])!={"valid","wrong-root","duplicate-key","expired"}:raise Refusal("fixture bundle schema")
    if not re.fullmatch("[0-9a-f]{64}",fixtures["rootPin"]):raise Refusal("fixture pin")
    (a.out/"public-fixtures.json").write_text(raw)
    for cluster in (["cmtc-a","cmtc-b"] if a.cluster=="both" else [a.cluster]):
        out=a.out/cluster;out.mkdir();Lab(a,cluster,fixtures,out).execute()
    print(json.dumps({"result":"publication-only cases passed","evidence":str(a.out),"TLSQualified":False,"Protected":False}))
if __name__=="__main__":
    try:main()
    except (Refusal,ValueError,OSError,subprocess.SubprocessError) as e:print(str(e),file=sys.stderr);sys.exit(1)
