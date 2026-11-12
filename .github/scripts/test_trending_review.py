import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import trending_review as review


class TrendingReviewTests(unittest.TestCase):
    def test_local_manifest_signals_include_architectures(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bucket = Path(temp_dir)
            (bucket / 'ruff.json').write_text(json.dumps({
                'homepage': 'https://github.com/astral-sh/ruff',
                'url': 'https://example.test/ruff.zip#/dl.7z',
                'hash': 'a' * 64,
                'bin': 'ruff.exe',
                'architecture': {
                    '64bit': {
                        'url': 'https://example.test/ruff-x64.zip',
                        'hash': 'c' * 64,
                    }
                },
            }), encoding='utf-8')
            manifests = review.get_local_manifests(bucket)

        signals = manifests['ruff']
        self.assertEqual(signals['repos'], {'astral-sh/ruff'})
        self.assertIn('https://example.test/ruff-x64.zip', signals['urls'])
        self.assertIn('c' * 64, signals['hashes'])
        self.assertIn('ruff.exe', signals['bins'])

    def test_name_and_repository_normalization(self):
        self.assertEqual(review.normalize_package_name('Notepad-Plus_Plus'), 'notepadplusplus')
        self.assertEqual(
            review.normalize_github_repo('https://github.com/Azure/acr-cli.git/'),
            'azure/acr-cli'
        )
        self.assertEqual(review.get_bucket_name('https://github.com/ScoopInstaller/Extras'), 'extras')

    def test_relative_date_handles_utc_and_invalid_input(self):
        self.assertIn('2026-01-01', review.format_relative_date('2026-01-01T00:00:00Z'))
        self.assertEqual(review.format_relative_date('not-a-date'), 'not-a-date')

    def test_github_token_is_used_for_api_requests(self):
        self.assertEqual(
            review.get_headers(token='test-token', github_api=True)['Authorization'],
            'Bearer test-token'
        )

    def test_punctuation_variant_is_a_manifest_name_signal(self):
        candidate = {
            'repo': 'example/notepad-plus-plus',
            'name': 'notepad-plus-plus',
            'package_names': {'notepad-plus-plus'},
            'win_assets': [],
        }
        evidence = review.find_manifest_duplicate_evidence(
            candidate,
            {'notepadplusplus': review.get_manifest_signals({})}
        )
        self.assertEqual(evidence['notepadplusplus'], {'manifest name'})

    def test_exact_url_or_hash_is_strong_evidence(self):
        manifest = review.get_manifest_signals({
            'url': 'https://example.test/tool.zip#/dl.7z',
            'hash': 'b' * 64,
        })
        candidate = {
            'repo': 'other/tool',
            'name': 'another-tool',
            'homepage': 'https://product.example',
            'win_assets': [{
                'name': 'tool-win64.zip',
                'url': 'https://example.test/tool.zip',
                'digest': 'sha256:' + ('b' * 64),
            }],
        }
        evidence = review.find_manifest_duplicate_evidence(candidate, {'existing-tool': manifest})
        self.assertEqual(evidence['existing-tool'], {'download URL', 'SHA-256'})
        self.assertTrue(review.has_strong_duplicate_evidence(evidence))

    def test_names_and_binary_alone_are_only_hints(self):
        candidate = {
            'repo': 'example/tool',
            'name': 'tool',
            'homepage': 'https://product.example/tool',
            'win_assets': [{'name': 'tool.exe', 'url': 'https://download.example/tool.zip'}],
        }
        manifest = review.get_manifest_signals({
            'homepage': candidate['homepage'],
            'bin': 'tool.exe',
        })
        evidence = review.find_manifest_duplicate_evidence(candidate, {'tool': manifest})
        self.assertEqual(evidence['tool'], {'homepage', 'binary name', 'manifest name'})
        self.assertFalse(review.has_strong_duplicate_evidence(evidence))

    def test_official_name_and_source_repository_are_strong_evidence(self):
        candidate = {
            'repo': 'astral-sh/ruff',
            'name': 'ruff',
            'package_names': {'ruff'},
            'win_assets': [],
        }
        manifest = {
            'name': 'ruff',
            'repository': 'https://github.com/ScoopInstaller/Main',
            'homepage': '',
            'homepage_repo': '',
            'signals': review.get_manifest_signals({
                'checkver': {'github': 'https://github.com/astral-sh/ruff'},
            }),
        }
        evidence = review.find_official_duplicate_evidence(candidate, [manifest])
        self.assertTrue(review.has_strong_duplicate_evidence(evidence))

    def test_semantic_alias_is_not_inferred(self):
        self.assertNotIn('nu', review.get_candidate_package_names('nushell/nushell'))

    def test_existing_issue_keys_preserve_repo_name_pairs(self):
        repos, names, pairs = review.collect_existing_issue_keys([{
            'title': '[Candidate]: notepad-plus-plus (GUI)',
            'body': '### Candidate: `NotepadPlusPlus`\nhttps://github.com/earendil-works/pi',
        }])
        self.assertIn('earendil-works/pi', repos)
        self.assertIn('notepadplusplus', names)
        self.assertIn(('earendil-works/pi', 'notepadplusplus'), pairs)

    @patch('builtins.print')
    @patch.object(review.subprocess, 'run')
    def test_generated_issue_body_only_adds_optional_hints(self, run, _print):
        run.return_value.returncode = 0
        run.return_value.stdout = 'https://github.com/ns0m/scoop-bucket/issues/1'
        candidate = {
            'name': 'tool',
            'repo': 'owner/tool',
            'type': 'CLI',
            'description': 'A tool',
            'trending_delta': '+10 stars this week',
            'stars': 10,
            'forks': 1,
            'open_issues': 0,
            'total_releases': 1,
            'tag': 'v1.0',
            'version': '1.0',
            'published_at': '2026-01-01T00:00:00Z',
            'created_at': '2025-01-01T00:00:00Z',
            'pushed_at': '2026-01-01T00:00:00Z',
            'license': 'MIT',
            'homepage': 'https://example.test',
            'win_assets': [{'name': 'tool-win64.zip', 'url': 'https://example.test/tool.zip', 'size': 1}],
        }

        review.create_candidate_issue(candidate, 'rust')

        body = run.call_args.args[0][run.call_args.args[0].index('--body') + 1]
        self.assertIn('#### :floppy_disk: Detected Windows binaries', body)
        self.assertNotIn('First: complete the duplicate check', body)
        self.assertNotIn('Packaging scope', body)


if __name__ == '__main__':
    unittest.main()
