import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from benchmark import gold_from_inspect, as_cyclonedx, compare_graphs, marker_active, installed_index
from packaging.requirements import Requirement


def make_inspect(os_name='linux', python_version='3.13', mid_version='2.0', include_leaf=True):
    packages = [
        ('demo', '1.0', [
            'mid[secure]>=2; python_version < "3.14"',
            'winonly>=1; sys_platform == "win32"',
            'never>=1; python_version < "3.8"',
        ]),
        ('mid','2.0' if mid_version == '2.0' else mid_version, ['leaf>=1; extra == "secure"']),
        ('winonly','1.0',[]),
        ('never','1.0',[]),
    ]
    if include_leaf:
        packages.append(('leaf','1.1',[]))
    return {'version':'1','pip_version':'25.1',
            'environment':{'sys_platform':os_name, 'python_version':python_version,
                           'platform_machine':'x86_64'},
            'installed':[{'metadata':{'name':n,'version':v,'requires_dist':r}}
                         for n,v,r in packages]}

class BenchTests(unittest.TestCase):
    def test_environment_markers(self):
        linux = gold_from_inspect(make_inspect(), ['demo==1.0'], project='t1')
        win = gold_from_inspect(make_inspect(os_name='win32'), ['demo==1.0'], project='t2')
        self.assertEqual({(e['from'],e['to']) for e in linux['edges']}, {('demo','mid'),('mid','leaf')})
        self.assertIn(('demo','winonly'), {(e['from'],e['to']) for e in win['edges']})
        self.assertNotIn('never', {n['name'] for n in win['nodes']})

    def test_extras_propagation(self):
        # mid[secure] activates leaf despite demo[] not requesting extras itself
        graph = gold_from_inspect(make_inspect(), ['demo==1.0'])
        self.assertIn(('mid','leaf'), {(e['from'],e['to']) for e in graph['edges']})
        self.assertEqual(next(n for n in graph['nodes'] if n['name']=='mid')['requested_extras'],['secure'])

    def test_extra_only_missing_context(self):
        inp=make_inspect()
        inp['installed'][0]['metadata']['requires_dist'] = ['mid>=2; extra == "full"']
        without=gold_from_inspect(inp,['demo==1.0'])
        with_extra=gold_from_inspect(inp,['demo[full]==1.0'])
        self.assertEqual(len(without['edges']),0)
        self.assertIn(('demo','mid'),{(e['from'],e['to']) for e in with_extra['edges']})

    def test_requested_extras_from_report(self):
        inp=make_inspect()
        inp['installed'][0]['metadata']['requires_dist'] = ['mid>=2; extra == "full"']
        report={'version':'1','install':[{'metadata':{'name':'demo','version':'1.0'},
                                        'requested':True,'requested_extras':['full']}], 'environment':inp['environment']}
        graph=gold_from_inspect(inp,[],report)
        self.assertIn(('demo','mid'),{(e['from'],e['to']) for e in graph['edges']})

    def test_missing_activated_requirement_excluded_from_gold(self):
        inp=make_inspect(include_leaf=False)
        g=gold_from_inspect(inp,['demo==1.0'])
        self.assertTrue(any(x['reason']=='activated-requirement-not-installed' for x in g['unresolved']))
        self.assertFalse(any(e['to']=='leaf' for e in g['edges']))

    def test_version_violation(self):
        inp=make_inspect(mid_version='1.0')
        graph=gold_from_inspect(inp,['demo==1.0'])
        self.assertTrue(any(x['reason']=='installed-version-violates-requirement' for x in graph['unresolved']))

    def test_report_mismatch_rejected(self):
        report={'version':'1','install':[{'metadata':{'name':'demo','version':'2.0'},'requested':True}], 'environment':{}}
        with self.assertRaises(ValueError):
            gold_from_inspect(make_inspect(), ['demo'],report)

    def test_cdx_roundtrip(self):
        gold=gold_from_inspect(make_inspect(),['demo==1.0'],project='fixture')
        cdx=as_cyclonedx(gold)
        comparison=compare_graphs(cdx,cdx)
        self.assertEqual(comparison['edge_overlap']['recall'],1.0)
        self.assertEqual(comparison['component_overlap']['precision'],1.0)

    def test_detect_missing_edge_in_generator(self):
        gold=gold_from_inspect(make_inspect(),['demo==1.0'],project='fixture')
        truth=as_cyclonedx(gold)
        observed=as_cyclonedx(gold)
        for row in observed['dependencies']:
            if row['ref'].endswith('demo@1.0'):
                row['dependsOn']=[]
        result=compare_graphs(truth,observed)
        self.assertEqual(result['edge_overlap']['fn'],1)

    def test_cyclic_and_self_referential_extras_terminate(self):
        cyclic_inspect = {
            'version': '1', 'pip_version': '25.1',
            'environment': {'sys_platform': 'linux', 'python_version': '3.11', 'platform_machine': 'x86_64'},
            'installed': [
                {'metadata': {'name': 'app', 'version': '1.0', 'requires_dist': ['pkg-a[x]>=1.0']}},
                {'metadata': {'name': 'pkg-a', 'version': '1.0', 'requires_dist': [
                    'pkg-b[y]>=1.0; extra == "x"',
                    'pkg-a[z]>=1.0; extra == "x"', # self-referential extra
                    'leaf>=1.0; extra == "z"'
                ]}},
                {'metadata': {'name': 'pkg-b', 'version': '1.0', 'requires_dist': [
                    'pkg-a[x]>=1.0; extra == "y"' # cyclic extra back to pkg-a
                ]}},
                {'metadata': {'name': 'leaf', 'version': '1.0', 'requires_dist': []}}
            ]
        }
        # Must terminate deterministically and discover leaf
        gold = gold_from_inspect(cyclic_inspect, ['app==1.0'], project='cycle-test')
        self.assertIn(('pkg-a', 'leaf'), {(e['from'], e['to']) for e in gold['edges']})
        self.assertIn(('pkg-a', 'pkg-b'), {(e['from'], e['to']) for e in gold['edges']})
        self.assertIn(('pkg-b', 'pkg-a'), {(e['from'], e['to']) for e in gold['edges']})
        self.assertEqual(len(gold['nodes']), 4)

if __name__=='__main__': unittest.main()
