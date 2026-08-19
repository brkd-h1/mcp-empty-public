import json,os,urllib.request
TOK=os.environ["TOK"]; NWO=os.environ["NWO"]; PERM=os.environ["PERM"]; O,R=NWO.split("/")
def rest(path,accept="application/vnd.github+json"):
    req=urllib.request.Request("https://api.github.com"+path,headers={
        "Authorization":"Bearer "+TOK,"Accept":accept,"User-Agent":"permsweep"})
    try:
        with urllib.request.urlopen(req) as r: return r.status, r.read()[:400].decode("utf8","replace")
    except Exception as e:
        try: return e.code, e.read()[:200].decode("utf8","replace")
        except Exception: return 0,str(e)[:120]
def gq(sel):
    q=json.dumps({"query":'query{repository(owner:"%s",name:"%s"){%s}}'%(O,R,sel)}).encode()
    req=urllib.request.Request("https://api.github.com/graphql",data=q,headers={
        "Authorization":"Bearer "+TOK,"Content-Type":"application/json","User-Agent":"permsweep"})
    try:
        with urllib.request.urlopen(req) as r: d=json.loads(r.read())
    except Exception as e:
        try: d=json.loads(e.read())
        except Exception: return "HTTPERR"
    if d.get("errors"): return "ERR:"+d["errors"][0].get("type","")+":"+d["errors"][0].get("message","")[:60]
    return "OK:"+json.dumps(d.get("data"))[:260]

PROBES=[
 ("contents-file",  lambda: rest("/repos/%s/contents/CANARY_SECRET.md"%NWO)),
 ("contents-raw",   lambda: rest("/repos/%s/contents/CANARY_SECRET.md"%NWO,"application/vnd.github.raw")),
 ("tree",           lambda: rest("/repos/%s/git/trees/HEAD?recursive=1"%NWO)),
 ("tarball",        lambda: rest("/repos/%s/tarball"%NWO)),
 ("commits",        lambda: rest("/repos/%s/commits"%NWO)),
 ("branches",       lambda: rest("/repos/%s/branches"%NWO)),
 ("act-secrets",    lambda: rest("/repos/%s/actions/secrets"%NWO)),
 ("act-variables",  lambda: rest("/repos/%s/actions/variables"%NWO)),
 ("act-runs",       lambda: rest("/repos/%s/actions/runs"%NWO)),
 ("act-artifacts",  lambda: rest("/repos/%s/actions/artifacts"%NWO)),
 ("deploykeys",     lambda: rest("/repos/%s/keys"%NWO)),
 ("hooks",          lambda: rest("/repos/%s/hooks"%NWO)),
 ("collabs",        lambda: rest("/repos/%s/collaborators"%NWO)),
 ("issues",         lambda: rest("/repos/%s/issues"%NWO)),
 ("pulls",          lambda: rest("/repos/%s/pulls"%NWO)),
 ("secretscan",     lambda: rest("/repos/%s/secret-scanning/alerts"%NWO)),
 ("codescan",       lambda: rest("/repos/%s/code-scanning/alerts"%NWO)),
 ("depalerts",      lambda: rest("/repos/%s/dependabot/alerts"%NWO)),
 ("depsecrets",     lambda: rest("/repos/%s/dependabot/secrets"%NWO)),
 ("codespaces-sec", lambda: rest("/repos/%s/codespaces/secrets"%NWO)),
 ("envs",           lambda: rest("/repos/%s/environments"%NWO)),
 ("pages",          lambda: rest("/repos/%s/pages"%NWO)),
 ("sbom",           lambda: rest("/repos/%s/dependency-graph/sbom"%NWO)),
 ("codeowners-err", lambda: rest("/repos/%s/codeowners/errors"%NWO)),
 ("community",      lambda: rest("/repos/%s/community/profile"%NWO)),
 ("teams",          lambda: rest("/repos/%s/teams"%NWO)),
 ("invitations",    lambda: rest("/repos/%s/invitations"%NWO)),
 ("rulesets",       lambda: rest("/repos/%s/rulesets"%NWO)),
 ("models-catalog", lambda: rest("/models/catalog/models")),
 ("installation",   lambda: rest("/installation/repositories")),
 ("user",           lambda: rest("/user")),
 ("gq-submodules",  lambda: gq('submodules(first:5){nodes{name gitUrl path}}')),
 ("gq-blob",        lambda: gq('object(expression:"HEAD:CANARY_SECRET.md"){... on Blob{text}}')),
 ("gq-tree",        lambda: gq('object(expression:"HEAD:"){... on Tree{entries{name}}}')),
 ("gq-issuetpl",    lambda: gq('issueTemplates{filename body}')),
 ("gq-codeowners",  lambda: gq('codeowners{errors{source line}}')),
 ("gq-fundinglinks",lambda: gq('fundingLinks{platform url}')),
 ("gq-contactlinks",lambda: gq('contactLinks{name url about}')),
 ("gq-prtpl",       lambda: gq('pullRequestTemplates{filename body}')),
 ("gq-depmanifest", lambda: gq('dependencyGraphManifests(first:5){nodes{filename dependencies(first:5){nodes{packageName}}}}')),
 ("gq-vulnalerts",  lambda: gq('vulnerabilityAlerts(first:3){nodes{vulnerableManifestPath vulnerableRequirements}}')),
 ("gq-deploykeys",  lambda: gq('deployKeys(first:3){nodes{title key}}')),
 ("gq-defbranch",   lambda: gq('defaultBranchRef{target{oid ... on Commit{message}}}')),
]
print("#### PERM=%s"%PERM)
for name,fn in PROBES:
    try: v=fn()
    except Exception as e: v=("EXC",str(e)[:80])
    if isinstance(v,tuple): st,body=v; out="%-4s %s"%(st,body.replace("\n"," ")[:170])
    else: out=str(v)[:200]
    print("P|%s|%-16s|%s"%(PERM,name,out))
