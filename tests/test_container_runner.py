import subprocess
import unittest
from unittest.mock import patch

from container_runner import run_container


class TestContainerLifetime(unittest.TestCase):
    def test_timeout_removes_only_its_own_container(self):
        command = ['docker', 'run', '--rm', 'some-image', 'python', '-c', 'pass']
        with patch('container_runner.subprocess.run', side_effect=[subprocess.TimeoutExpired(command, 1),
                                                                 subprocess.CompletedProcess([], 0)]) as execute:
            with self.assertRaises(subprocess.TimeoutExpired):
                run_container(command, timeout=1)
        created_name = command[command.index('--name') + 1]
        self.assertTrue(created_name.startswith('sbom-research-'))
        self.assertEqual(execute.call_args_list[1].args[0], ['docker', 'rm', '-f', created_name])

    def test_refuses_to_take_ownership_of_existing_names(self):
        with patch('container_runner.subprocess.run') as execute:
            for options in (['--name', 'user-container'], ['--name=user-container']):
                with self.assertRaises(ValueError):
                    run_container(['docker', 'run', *options, 'image'], timeout=1)
            execute.assert_not_called()
