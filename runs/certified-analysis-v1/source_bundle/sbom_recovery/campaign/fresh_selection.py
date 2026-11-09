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


def replace_failed(cohort, outcomes):
    """Use only terminal eligibility failures; never substitute an interrupted job."""
    from copy import deepcopy
    result=deepcopy(cohort)
    projects=result['projects']
    if any(r['name'] not in outcomes for r in projects):
        raise ValueError('Unreported captures must be resumed, not replaced')
    if any(outcomes[r['name']]['status'] not in ('COMPLETE','FAILED','OBSERVATION_INVALID') for r in projects):
        raise ValueError('Capture eligibility is not terminal')
    used_names={r['name'] for r in projects}
    used_families={r['family_id'] for r in projects}
    for history in result.get('replacement_history',[]):
        used_names.add(history['excluded_name']);used_families.add(history['excluded_family_id'])
    changes=[]
    for index,row in enumerate(projects):
        outcome=outcomes[row['name']]
        if outcome['status']=='COMPLETE':continue
        reserve=next((r for r in result['reserves'][row['partition']]
                      if r['name'] not in used_names and r['family_id'] not in used_families),None)
        event={'excluded_name':row['name'],'excluded_version':row['version'],'excluded_family_id':row['family_id'],
               'partition':row['partition'],'eligibility_failure':outcome['status'],
               'evidence_sha256':outcome['evidence_sha256'],'replacement_name':reserve['name'] if reserve else None}
        if reserve:
            projects[index]=reserve;used_names.add(reserve['name']);used_families.add(reserve['family_id'])
        changes.append(event)
    result['reserves']={fold:[r for r in rows if r['name'] not in used_names and r['family_id'] not in used_families]
                        for fold,rows in result['reserves'].items()}
    result['replacement_history']=result.get('replacement_history',[])+changes
    result['status']='PROVISIONAL_BUILD_COHORT' if all(e['replacement_name'] for e in changes) else 'RESERVE_SHORTFALL'
    result['final_build_valid_cohort']=False
    result['replacement_metrics_used']=[]
    return result
