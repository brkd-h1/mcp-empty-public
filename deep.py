import json,os,urllib.request
TOK=os.environ["TOK"]; NWO=os.environ["NWO"]; O,R=NWO.split("/")
def gq(sel,label):
    q=json.dumps({"query":'query{repository(owner:"%s",name:"%s"){%s}}'%(O,R,sel)}).encode()
    req=urllib.request.Request("https://api.github.com/graphql",data=q,headers={
        "Authorization":"Bearer "+TOK,"Content-Type":"application/json","User-Agent":"deep"})
    try:
        with urllib.request.urlopen(req) as r: d=json.loads(r.read())
    except Exception as e:
        try: d=json.loads(e.read())
        except Exception as e2: print("D|%s|HTTPERR"%label); return
    if d.get("errors"):
        e=d["errors"][0]; print("D|%s|ERR|%s|%s"%(label,e.get("type"),e.get("message","")[:90])); return
    print("D|%s|OK|%s"%(label,json.dumps(d.get("data",{}).get("repository"))[:900]))
def rest(path,label,accept="application/vnd.github+json"):
    req=urllib.request.Request("https://api.github.com"+path,headers={"Authorization":"Bearer "+TOK,"Accept":accept,"User-Agent":"deep"})
    try:
        with urllib.request.urlopen(req) as r: print("R|%s|%s|%s"%(label,r.status,r.read()[:700].decode("utf8","replace").replace("\n"," ")))
    except Exception as e:
        try: print("R|%s|%s|%s"%(label,e.code,e.read()[:200].decode("utf8","replace").replace("\n"," ")))
        except Exception: print("R|%s|0|%s"%(label,str(e)[:100]))
gq('dependencyGraphManifests(first:10){totalCount nodes{id filename blobPath parseable exceedsMaxSize dependenciesCount dependencies(first:20){nodes{packageName packageManager requirements hasDependencies}}}}','depmanifests')
gq('deployKeys(first:10){totalCount nodes{id title key readOnly createdAt verified}}','deploykeys')
gq('vulnerabilityAlerts(first:10){totalCount nodes{number state vulnerableManifestFilename vulnerableManifestPath vulnerableRequirements dependencyScope securityVulnerability{package{name ecosystem} vulnerableVersionRange advisory{ghsaId summary}}}}','vulnalerts')
gq('packages(first:10){totalCount nodes{id name packageType latestVersion{version files(first:5){nodes{name size}}}}}','packages')
gq('rulesets(first:10,includeParents:true){totalCount nodes{id name target enforcement}}','rulesets')
gq('projectsV2(first:10){totalCount nodes{id title number readme shortDescription}}','projectsv2')
gq('discussions(first:10){totalCount nodes{number title body}}','discussions')
gq('collaborators(first:20){totalCount nodes{login email name}edges{permission}}','collaborators')
gq('mentionableUsers(first:20){totalCount nodes{login email name}}','mentionable')
gq('languages(first:10){totalCount totalSize edges{size node{name}}}','languages')
gq('licenseInfo{key name spdxId body}','licenseinfo')
gq('planFeatures{__typename}','planfeatures')
gq('pinnedEnvironments(first:5){nodes{__typename}}','pinnedenvs')
gq('recentProjects(first:5){nodes{title readme}}','recentprojects')
gq('issueFields(first:10){nodes{__typename}}','issuefields')
gq('repositoryTopics(first:10){nodes{topic{name}}}','topics')
gq('forks(first:5){nodes{nameWithOwner isPrivate}}','forks')
gq('packages(first:5,packageType:NPM){nodes{name}}','packages-npm')
rest("/repos/%s/dependency-graph/sbom"%NWO,"sbom")
rest("/repos/%s/dependency-graph/compare/main"%NWO,"depcompare")
rest("/repos/%s/vulnerability-alerts"%NWO,"vulnalerts-rest")
rest("/repos/%s/keys"%NWO,"keys-rest")
rest("/repos/%s/languages"%NWO,"languages-rest")
