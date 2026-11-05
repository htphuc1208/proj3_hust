"""Chronological, family-disjoint root assignment from public preprediction data."""
from datetime import datetime
from hashlib import sha256


def instant(value):
    result=datetime.fromisoformat(value.replace('Z','+00:00'))
    if result.tzinfo is None:raise ValueError('Release timestamp lacks timezone')
    return result


def assign(pool, identities, exclusions, screened, protocol):
    if identities['old_repositories_unresolved']:
        raise ValueError('Prior cohort identities remain unresolved')
    checks={row['name']:row for row in identities['candidate_checks']}
    old_names=set(exclusions['names']);old_repos=set(exclusions['repositories'])
    development_only=set(screened['names'])
    rows=[];rejections=[]
    for row in pool['records']:
        if row['status']!='RELEASE_ELIGIBLE':continue
        check=checks.get(row['name'])
        reason=None
        if row['name'] in old_names or row['repository'] in old_repos:reason='ORIGINAL_ROOT'
        elif not check or check['identity_status']!='IDENTITY_OBSERVED':reason='IDENTITY_UNKNOWN'
        elif any(type(check.get(k)) is not int or check[k]<=0 for k in ['family_id','repository_id']):reason='IDENTITY_INVALID'
        elif check['known_old_family_overlap'] is not False:reason='ORIGINAL_FAMILY_OR_UNKNOWN'
        if reason:
            rejections.append({'name':row['name'],'reason':reason});continue
        rows.append({**row,'family_id':check['family_id'],'repository_id':check['repository_id'],
                     'canonical_repository':check['canonical_repository']})
    rows.sort(key=lambda r:sha256(f"{protocol['selection_seed']}:{r['candidate']}".encode()).hexdigest())
    selected=[];used_families=set();used_names=set();counts={k:0 for k in protocol['target_projects']}
    reserves={k:[] for k in counts}
    for partition in protocol['assignment_priority']:
        window=protocol['release_windows'][partition]
        for row in rows:
            release=row.get('eligible',{}).get(partition)
            if not release or (partition!='development' and row['name'] in development_only):continue
            timestamp=instant(release['released_at'])
            if (timestamp>instant(window['end']) or (window.get('start') and timestamp<instant(window['start']))):
                raise ValueError('Registry release falls outside declared window')
            if row['name'] in used_names or row['family_id'] in used_families:continue
            project={k:v for k,v in row.items() if k!='eligible'}|release|{'partition':partition}
            if counts[partition]<protocol['target_projects'][partition]:
                selected.append(project);counts[partition]+=1
                used_names.add(row['name']);used_families.add(row['family_id'])
            else:reserves[partition].append(project)
    # Reserve rows are alternatives, not extra selected roots. Families already
    # assigned in later partitions must never be used for replacement.
    reserves={k:[r for r in v if r['family_id'] not in used_families and r['name'] not in used_names] for k,v in reserves.items()}
    return {'projects':selected,'counts':counts,'reserves':reserves,'rejections':rejections,
            'status':'PROVISIONAL_BUILD_COHORT' if counts==protocol['target_projects'] else 'ASSIGNMENT_SHORTFALL',
            'final_build_valid_cohort':False,'method_predictions_run':False,
            'family_scope':'Publisher-observed GitHub network roots; unregistered manual clones remain a validity threat',
            'selection_metrics_used':[]}
