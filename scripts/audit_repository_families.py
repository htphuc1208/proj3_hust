#!/usr/bin/env python3
"""Freeze publisher repository identities before cohort assignment or prediction."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import sys

import httpx

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from research_core import load,digest,now
from sbom_recovery.storage import save


class RepositoryMeta(HTMLParser):
    def __init__(self):
        super().__init__(); self.fields=defaultdict(list); self.tags=[]

    def handle_starttag(self,tag,attrs):
        if tag!='meta':return
        attrs=dict(attrs);name=attrs.get('name','')
        prefix='octolytics-dimension-repository_'
        if name.startswith(prefix):
            self.fields[name[len(prefix):]].append(attrs.get('content'))
            self.tags.append(self.get_starttag_text())

    def identity(self):
        required=['id','nwo','is_fork','network_root_id','network_root_nwo']
        if any(len(self.fields[k])!=1 for k in required):raise ValueError('Missing/ambiguous repository identity fields')
        row={k:self.fields[k][0] for k in required}
        if (not re.fullmatch(r'\d+',row['id']) or not re.fullmatch(r'\d+',row['network_root_id'])
                or row['is_fork'] not in ('true','false')
                or any(not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',row[k]) for k in ['nwo','network_root_nwo'])):
            raise ValueError('Invalid repository identity fields')
        if row['is_fork']=='false' and (row['id']!=row['network_root_id'] or row['nwo'].lower()!=row['network_root_nwo'].lower()):
            raise ValueError('Inconsistent repository family metadata')
        return {'repository_id':int(row['id']),'canonical_repository':row['nwo'].lower(),
                'is_fork':row['is_fork']=='true','family_id':int(row['network_root_id']),
                'family_repository':row['network_root_nwo'].lower()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pool',required=True);parser.add_argument('--out',required=True)
    parser.add_argument('--workers',type=int,default=6)
    args=parser.parse_args()
    pool=Path(args.pool);out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    shutil.copyfile(__file__,out/'executed-runner.py')
    old=load(pool/'exclusions.json');candidates=load(pool/'pool.json')['records']
    repositories=sorted(set(old['repositories'])|{r['repository'] for r in candidates if r['status']=='RELEASE_ELIGIBLE'})
    save(out/'plan.json',{'pool_sha256':digest(pool/'pool.json'),'exclusions_sha256':digest(pool/'exclusions.json'),
         'repositories':repositories,'source_sha256':digest(__file__),'model_calls':0,'created_at':now(),
         'identity_source':'GitHub publisher HTML repository metadata; public fields only, no auth/cookies retained',
         'family_scope':'Current GitHub-registered network roots; manual/unregistered forks are not proven absent'})
    raw=out/'publisher-fields';raw.mkdir()
    def fetch(repository):
        url='https://github.com/'+repository
        row={'requested_repository':repository,'url':url,'queried_at':now()}
        try:
            response=httpx.get(url,timeout=40,follow_redirects=True,headers={'User-Agent':'sbom-research-identity/1'})
            row.update(http_status=response.status_code,effective_url=str(response.url),html_sha256=sha256(response.content).hexdigest())
            if response.status_code!=200:return {**row,'status':'UNAVAILABLE'}
            parsed=RepositoryMeta();parsed.feed(response.text)
            identity=parsed.identity()
            expected='https://github.com/'+identity['canonical_repository']
            if str(response.url).lower().rstrip('/')!=expected:raise ValueError('Canonical URL disagrees with publisher metadata')
            name=sha256(repository.encode()).hexdigest()+'.json'
            save(raw/name,{'source_url':url,'effective_url':str(response.url),'queried_at':row['queried_at'],
                 'html_sha256':row['html_sha256'],'repository_meta_tags':parsed.tags})
            return {**row,**identity,'status':'IDENTITY_OBSERVED','publisher_fields_file':str((raw/name).relative_to(out)),
                    'publisher_fields_sha256':digest(raw/name)}
        except Exception as exc:return {**row,'status':'UNKNOWN','error_type':type(exc).__name__}
    records=[]
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for index,row in enumerate(executor.map(fetch,repositories),1):
            records.append(row)
            if index%25==0:
                save(out/'progress.json',{'finished':index,'total':len(repositories),'status_counts':dict(Counter(r['status'] for r in records))})
                print('repository identities',index,'/',len(repositories),flush=True)
    by_name={r['requested_repository']:r for r in records}
    old_families={r['family_id'] for r in records if r['requested_repository'] in old['repositories'] and r['status']=='IDENTITY_OBSERVED'}
    checks=[]
    for candidate in candidates:
        if candidate['status']!='RELEASE_ELIGIBLE':continue
        identity=by_name[candidate['repository']]
        checks.append({'name':candidate['name'],'requested_repository':candidate['repository'],
             'identity_status':identity['status'],'repository_id':identity.get('repository_id'),
             'family_id':identity.get('family_id'),'canonical_repository':identity.get('canonical_repository'),
             'known_old_family_overlap':identity.get('family_id') in old_families if identity['status']=='IDENTITY_OBSERVED' else None})
    save(out/'identities.json',{'status':'IDENTITIES_CAPTURED_WITH_EXPLICIT_UNKNOWNS','records':records,'candidate_checks':checks,
         'status_counts':dict(Counter(r['status'] for r in records)),
         'old_repositories_observed':sum(r['requested_repository'] in old['repositories'] and r['status']=='IDENTITY_OBSERVED' for r in records),
         'old_repositories_unresolved':[r['requested_repository'] for r in records if r['requested_repository'] in old['repositories'] and r['status']!='IDENTITY_OBSERVED'],
         'known_old_family_overlap_count':sum(r['known_old_family_overlap'] is True for r in checks),
         'model_calls':0,'method_outcomes_read':False,'manual_fork_detection':'UNMEASURED'})


if __name__=='__main__':main()
