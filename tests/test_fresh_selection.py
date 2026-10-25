"""Chronology and family separation are evaluated before any model outcomes."""
from copy import deepcopy
import unittest

from sbom_recovery.fresh_selection import assign,replace_failed


class FreshSelectionTests(unittest.TestCase):
    def setUp(self):
        self.protocol={'selection_seed':42,'target_projects':{'development':1,'calibration':1,'test':1},
            'assignment_priority':['test','calibration','development'],
            'release_windows':{
                'development':{'start':None,'end':'2025-12-31T23:59:59Z'},
                'calibration':{'start':'2026-01-01T00:00:00Z','end':'2026-06-30T23:59:59Z'},
                'test':{'start':'2026-07-01T00:00:00Z','end':'2026-10-28T16:59:59Z'}}}
        self.pool={'records':[
            self.row('early',{'development':'2025-10-01T00:00:00Z'}),
            self.row('middle',{'calibration':'2026-03-01T00:00:00Z'}),
            self.row('late',{'test':'2026-09-01T00:00:00Z'})]}
        self.identities={'old_repositories_unresolved':[],'candidate_checks':[
            {'name':name,'identity_status':'IDENTITY_OBSERVED','known_old_family_overlap':False,
             'family_id':i,'repository_id':i,'canonical_repository':'org/'+name}
            for i,name in enumerate(['early','middle','late'],1)]}
        self.exclusions={'names':[],'repositories':[]}

    def row(self,name,dates):
        return {'candidate':name,'name':name,'repository':'org/'+name,'status':'RELEASE_ELIGIBLE',
                'eligible':{fold:{'version':'1','released_at':date} for fold,date in dates.items()}}

    def run_assignment(self,screened=()):
        return assign(self.pool,self.identities,self.exclusions,{'names':list(screened)},self.protocol)

    def test_untouched_release_partitions_are_family_disjoint_and_deterministic(self):
        result=self.run_assignment()
        self.assertEqual(result['counts'],self.protocol['target_projects'])
        self.assertEqual({r['name']:r['partition'] for r in result['projects']},
                         {'early':'development','middle':'calibration','late':'test'})
        self.pool['records'].reverse()
        self.assertEqual(self.run_assignment()['projects'],result['projects'])

    def test_development_screened_root_never_migrates_into_heldout(self):
        self.pool['records'][0]['eligible']['test']={'version':'2','released_at':'2026-09-01T00:00:00Z'}
        result=self.run_assignment(['early'])
        self.assertEqual(next(r for r in result['projects'] if r['name']=='early')['partition'],'development')
        result=self.run_assignment(['early','late'])
        self.assertEqual(result['status'],'ASSIGNMENT_SHORTFALL')
        self.assertEqual(result['counts']['test'],0)

    def test_forks_and_package_aliases_cannot_enter_two_partitions(self):
        self.identities['candidate_checks'][1]['family_id']=3
        result=self.run_assignment()
        self.assertEqual(result['counts']['test'],1)
        self.assertEqual(result['counts']['calibration'],0)
        self.assertEqual(len({r['family_id'] for r in result['projects']}),len(result['projects']))

    def test_known_old_or_unknown_repository_identity_is_excluded(self):
        for value in [True,None]:
            self.identities['candidate_checks'][2]['known_old_family_overlap']=value
            result=self.run_assignment()
            self.assertFalse(any(r['name']=='late' for r in result['projects']))
        self.identities['candidate_checks'][2]['known_old_family_overlap']=False
        self.identities['candidate_checks'][2]['identity_status']='UNKNOWN'
        self.assertEqual(self.run_assignment()['counts']['test'],0)

    def test_release_outside_window_is_not_silently_reassigned(self):
        self.pool['records'][2]['eligible']['test']['released_at']='2026-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError,'outside'):self.run_assignment()

    def test_unresolved_original_identity_blocks_claim_of_disjointness(self):
        self.identities['old_repositories_unresolved']=['old/moved']
        with self.assertRaisesRegex(ValueError,'unresolved'):self.run_assignment()

    def test_replacements_preserve_partition_and_never_reuse_a_family(self):
        cohort=self.run_assignment()
        template=next(r for r in cohort['projects'] if r['name']=='early')
        cohort['reserves']['development']=[{**template,'name':'bad-alias','family_id':3},
                                           {**template,'name':'reserve','family_id':10}]
        outcomes={r['name']:{'status':'FAILED' if r['name']=='early' else 'COMPLETE','evidence_sha256':'a'*64}
                  for r in cohort['projects']}
        result=replace_failed(cohort,outcomes)
        self.assertEqual(next(r for r in result['projects'] if r['partition']=='development')['name'],'reserve')
        self.assertEqual(cohort['projects'][2]['name'],'early')
        self.assertEqual(result['replacement_history'][0]['excluded_name'],'early')

    def test_interrupted_or_missing_capture_cannot_be_replaced_as_a_failure(self):
        cohort=self.run_assignment()
        with self.assertRaisesRegex(ValueError,'resumed'):replace_failed(cohort,{})
        outcomes={r['name']:{'status':'RUNNING','evidence_sha256':'a'*64} for r in cohort['projects']}
        with self.assertRaisesRegex(ValueError,'terminal'):replace_failed(cohort,outcomes)


if __name__=='__main__':unittest.main()
