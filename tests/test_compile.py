import ast
import ipaddress
import json
import logging
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock


# Load functions without launching downloads or the build pipeline.
def load_functions():
    tree = ast.parse((Path(__file__).resolve().parents[1] / 'compile.py').read_text())
    scope = dict(ipaddress=ipaddress, json=json, Path=Path, subprocess=subprocess,
                 tempfile=tempfile, logger=logging.getLogger('test'),
                 args=SimpleNamespace(exec='sing-box', debug=False))
    module = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef)], type_ignores=[])
    exec(compile(module, 'compile.py', 'exec'), scope)
    return scope


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.ns = load_functions()
        self.values = [[] for _ in range(6)]

    def parse(self, line):
        self.ns['process_line'](line, *self.values, source='test.txt', line_number=7)

    def test_types_and_preservation(self):
        for line in ['www.wow.com', 'domain:www.exact.test',
                     'domain_suffix:www.suffix.test', r'domain_regex:^AbC\.#:test$',
                     '192.0.2.1', '2001:db8::1', 'ip_cidr:2001:db8::2/64', '# comment']:
            self.parse(line)
        ips, domains, suffixes, regex, _, _ = self.values
        self.assertEqual(ips, ['192.0.2.1/32', '2001:db8::1/128', '2001:db8::/64'])
        self.assertEqual(domains, ['www.exact.test'])
        self.assertEqual(suffixes, ['wow.com', 'www.suffix.test'])
        self.assertEqual(regex, [r'^AbC\.#:test$'])

    def test_sources_and_aliases(self):
        self.ns['get_srs_file'] = Mock(side_effect=lambda url: url)
        self.ns['get_list_adguard'] = Mock(side_effect=lambda url: url)
        self.ns['get_list_text_format'] = Mock(return_value=['domain:nested.test'])
        for line in ['srs:https://a.test/a.srs#fragment', '?? https://a.test/b.srs',
                     'list:https://a.test/list', ';; https://a.test/list',
                     'adguard:https://a.test/filter', '|| https://a.test/filter']:
            self.parse(line)
        self.assertEqual(self.values[1], ['nested.test', 'nested.test'])
        self.assertEqual(len(self.values[4]), 2)
        self.assertEqual(self.values[5], ['https://a.test/a.srs#fragment', 'https://a.test/b.srs'])

    def test_errors_have_location(self):
        for line in ['unknown:value', 'domain:', 'srs:', 'ip_cidr:bad', 'domain_regex:[']:
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, 'test.txt:7:'):
                self.parse(line)
        self.ns['get_list_text_format'] = Mock(return_value=['# comment', 'bad:value'])
        with self.assertRaisesRegex(ValueError, 'https://a.test/list:2:'):
            self.parse('list:https://a.test/list')

    def test_build_and_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / 'sample'
            rules.mkdir()
            (rules / 'a.txt').write_text('domain:exact.test\ndomain_suffix:tree.test\n'
                                       'domain_regex:^rx[0-9]+\\.test$\nsrs:https://a.test/a.srs\n')
            (rules / 'b.txt').write_text('2001:db8::1\nsrs:https://a.test/b.srs\n')
            self.ns['get_srs_file'] = Mock(side_effect=lambda url: url)
            self.ns['parse_srs_files'] = Mock(return_value=([], [], [], []))
            self.ns['OUTPUT_DIR'] = root
            self.ns['process_dir'](rules)
            self.assertEqual(set(self.ns['parse_srs_files'].call_args.args[0]),
                             {'https://a.test/a.srs', 'https://a.test/b.srs'})
            def matches(name, target):
                r = subprocess.run(['sing-box', 'rule-set', 'match', '-f', 'binary',
                                    str(root / name), target], capture_output=True, text=True, check=True)
                return 'match rules.' in r.stdout + r.stderr
            for target in ['exact.test', 'tree.test', 'sub.tree.test', 'rx42.test']:
                self.assertTrue(matches('sample.srs', target), target)
            for target in ['sub.exact.test', 'sub.rx42.test', 'other.test']:
                self.assertFalse(matches('sample.srs', target), target)
            self.assertTrue(matches('sample-ip.srs', '2001:db8::1'))
            self.assertFalse(matches('sample-ip.srs', '2001:db8::2'))

    def test_regex_does_not_remove_suffix(self):
        domains, suffixes = self.ns['normalize_domains']([], ['example.com'], [r'^example\.com$'])
        self.assertEqual(suffixes, ['example.com'])


if __name__ == '__main__':
    unittest.main()
