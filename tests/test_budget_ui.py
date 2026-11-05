"""Local UI input boundaries and credential-free responses."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.request import urlopen,Request
from urllib.error import HTTPError
from http.server import HTTPServer

from ui import budget_api
from ui.server import RecoveryUIHandler,get_run_details


class BudgetUITests(unittest.TestCase):
    def test_run_identifiers_cannot_escape_output_root(self):
        for value in ['../.env','/tmp/secret','..','a/b','a\\b']:
            with self.subTest(value=value),self.assertRaises(ValueError):budget_api.safe_root(value)
        self.assertIsNone(get_run_details('../.env'))

    def test_credential_fields_and_arbitrary_paths_are_not_job_inputs(self):
        with self.assertRaises(ValueError):budget_api.start({'api_key':'fixture-only'})
        with self.assertRaises(ValueError):budget_api.start({'target':'/tmp'})

    def test_uploaded_document_must_be_native_sbom_object(self):
        fixture=[{'name':'fixture','scanners':['syft.spdx.json']}]
        for value in [[],None,'not JSON',{}]:
            with patch.object(budget_api,'projects',return_value=fixture),self.assertRaises(ValueError):
                budget_api.start({'project':'fixture','scanner':'syft.spdx.json','document':value})

    def test_budget_and_scanner_are_allowlisted(self):
        fixture=[{'name':'fixture','scanners':['syft.spdx.json']}]
        for budget in [True,-1,100,0]:
            with patch.object(budget_api,'projects',return_value=fixture),self.assertRaises(ValueError):
                budget_api.start({'project':'fixture','scanner':'syft.spdx.json','budget':budget})
        with patch.object(budget_api,'projects',return_value=fixture),self.assertRaises(ValueError):
            budget_api.start({'project':'fixture','scanner':'../../.env','budget':4})

    def test_default_and_explicit_null_allow_unrestricted_without_launching_jobs(self):
        fixture=[{'name':'fixture','scanners':['syft.spdx.json']}]
        with patch.object(budget_api,'projects',return_value=fixture),patch.object(budget_api.threading,'Thread') as thread,patch.dict(budget_api.JOBS,{},clear=True):
            for extra in [{},{'budget':None}]:
                result=budget_api.start({'project':'fixture','scanner':'syft.spdx.json',**extra})
                self.assertIn('job_id',result)
            self.assertEqual(thread.return_value.start.call_count,2)


class LocalHTTPTests(unittest.TestCase):
    def setUp(self):
        self.server=HTTPServer(('127.0.0.1',0),RecoveryUIHandler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=3)

    def test_settings_report_presence_without_returning_credential(self):
        with patch.dict('os.environ',{'NETMIND_API_KEY':'fixture-credential-never-return'}):
            with urlopen(self.base+'/api/agent/settings') as response:
                text=response.read().decode();data=json.loads(text)
        self.assertTrue(data['gateway_configured'])
        self.assertNotIn('fixture-credential',text)
        self.assertEqual(set(data),{'gateway_configured','models'})

    def test_cross_origin_job_submission_is_rejected_without_execution(self):
        request=Request(self.base+'/api/agent/run',data=b'{}',headers={'Content-Type':'application/json','Origin':'https://untrusted.invalid'})
        with patch.object(budget_api,'start') as start,self.assertRaises(HTTPError) as error:urlopen(request)
        self.assertEqual(error.exception.code,403);start.assert_not_called()

    def test_homepage_is_connected_agent_interface(self):
        with urlopen(self.base+'/') as response:text=response.read().decode()
        self.assertIn('SBOM Risk Studio',text)
        self.assertIn('/agent.js',text)
        self.assertIn('id="reachability-pilot"',text)
        with self.assertRaises(HTTPError):urlopen(self.base+'/.env')

    def test_reachability_route_returns_read_only_pilot_state(self):
        with patch('ui.reachability_api.latest',return_value={'status':'UNAVAILABLE'}):
            with urlopen(self.base+'/api/agent/reachability') as response:
                self.assertEqual(json.loads(response.read()),{'status':'UNAVAILABLE'})

    def test_nonlocal_host_header_cannot_use_local_credentials(self):
        request=Request(self.base+'/api/agent/settings',headers={'Host':'untrusted.invalid'})
        with self.assertRaises(HTTPError) as error:urlopen(request)
        self.assertEqual(error.exception.code,403)


if __name__=='__main__':unittest.main()
