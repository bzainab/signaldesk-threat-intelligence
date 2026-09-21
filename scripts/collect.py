"""Collect public intelligence with provenance. No credentials or third-party packages."""
import argparse
import concurrent.futures
import datetime as dt
import json
from pathlib import Path
import urllib.request

KEV = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
EPSS = 'https://api.first.org/data/v1/epss'
ATTACK = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json'

def fetch_json(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'SignalDesk/1.0 (public intelligence research)'})
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)

def collect(output):
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    kev = fetch_json(KEV)
    rows = sorted(kev['vulnerabilities'], key=lambda x: (x['dateAdded'], x['cveID']), reverse=True)
    epss, errors = {}, []
    batches = [rows[i:i+80] for i in range(0, min(len(rows), 240), 80)]
    for batch in batches:
        try:
            result = fetch_json(EPSS + '?cve=' + ','.join(x['cveID'] for x in batch) + '&limit=100')
            epss.update({x['cve']: x for x in result['data']})
        except Exception as exc:
            errors.append('EPSS: ' + type(exc).__name__)
    normalized = []
    for row in rows:
        e = epss.get(row['cveID'], {})
        normalized.append(dict(id=row['cveID'], title=row['vulnerabilityName'], vendor=row['vendorProject'],
            product=row['product'], description=row['shortDescription'], added=row['dateAdded'],
            due=row['dueDate'], ransomware=row.get('knownRansomwareCampaignUse') == 'Known',
            action=row['requiredAction'], notes=row.get('notes',''), cwes=row.get('cwes',[]),
            epss=float(e['epss']) if e else None, percentile=float(e['percentile']) if e else None,
            epssDate=e.get('date')))
    bundle = fetch_json(ATTACK)
    objects = {o['id']: o for o in bundle['objects'] if not o.get('revoked') and not o.get('x_mitre_deprecated')}
    techniques, groups = {}, []
    for obj in objects.values():
        refs = [r for r in obj.get('external_references',[]) if r.get('source_name') == 'mitre-attack']
        if obj['type'] == 'attack-pattern' and refs:
            ref = refs[0]
            techniques[obj['id']] = dict(id=ref['external_id'], name=obj['name'], url=ref.get('url'),
                tactics=[p['phase_name'] for p in obj.get('kill_chain_phases',[])])
    links = {}
    for obj in objects.values():
        if obj['type'] == 'relationship' and obj.get('relationship_type') == 'uses' and obj.get('target_ref') in techniques:
            links.setdefault(obj['source_ref'],set()).add(obj['target_ref'])
    for obj in objects.values():
        if obj['type'] != 'intrusion-set':
            continue
        refs = [r for r in obj.get('external_references',[]) if r.get('source_name') == 'mitre-attack']
        if refs:
            groups.append(dict(id=refs[0]['external_id'], name=obj['name'], aliases=obj.get('aliases',[]),
                description=obj.get('description','')[:2400], url=refs[0].get('url'), modified=obj['modified'],
                techniques=sorted([techniques[t] for t in links.get(obj['id'],[])],key=lambda t:t['id'])))
    result = dict(collectedAt=now, catalogDate=kev['dateReleased'], vulnerabilities=normalized,
        groups=sorted(groups,key=lambda g:g['name'].lower()),
        sources=[dict(name='CISA KEV',url=KEV,records=len(normalized)),
                 dict(name='FIRST EPSS',url=EPSS,records=len(epss)),
                 dict(name='MITRE ATT&CK',url=ATTACK,records=len(groups))], errors=errors)
    output = Path(output)
    output.parent.mkdir(parents=True,exist_ok=True)
    temp = output.with_suffix('.tmp')
    temp.write_text(json.dumps(result,ensure_ascii=False,separators=(',',':')),encoding='utf-8')
    temp.replace(output)
    return result

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='data/intelligence.json')
    args=parser.parse_args()
    result=collect(args.output)
    print(json.dumps(dict(vulnerabilities=len(result['vulnerabilities']),groups=len(result['groups']),sources=result['sources'],errors=result['errors']),indent=2))
