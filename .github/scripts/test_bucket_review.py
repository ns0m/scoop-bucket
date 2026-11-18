import unittest

import bucket_review as review
from trending_duplicates import get_manifest_signals


class BucketReviewTests(unittest.TestCase):
    def test_lookup_candidates_include_manifest_names_and_source_repository(self):
        manifests = [{
            'name': 'tool-name',
            'signals': get_manifest_signals({
                'homepage': 'https://github.com/example/tool',
                'url': 'https://example.test/tool.zip',
                'checkver': 'github',
            }),
        }]

        candidates = review.get_official_lookup_candidates(manifests)

        self.assertEqual(candidates[0]['repo'], 'example/tool')
        self.assertTrue({'tool-name', 'toolname'} <= candidates[0]['package_names'])

    def test_duplicate_report_compares_urls_and_labels_weak_matches(self):
        local = {
            'name': 'tool',
            'path': review.Path('bucket/tool.json'),
            'signals': get_manifest_signals({
                'homepage': 'https://example.test/tool',
                'url': 'https://example.test/tool.zip',
                'hash': 'a' * 64,
                'bin': 'tool.exe',
            }),
        }
        official = [
            {
                'name': 'tool',
                'repository': 'https://github.com/ScoopInstaller/Main',
                'homepage': 'https://example.test/tool',
                'homepage_repo': '',
                'file_path': 'bucket/tool.json',
                'signals': get_manifest_signals({
                    'homepage': 'https://example.test/tool',
                    'url': 'https://example.test/tool.zip',
                    'hash': 'a' * 64,
                    'bin': 'tool.exe',
                }),
            },
            {
                'name': 'other-tool',
                'repository': 'https://github.com/ScoopInstaller/Extras',
                'homepage': 'https://elsewhere.test',
                'homepage_repo': '',
                'signals': get_manifest_signals({'bin': 'tool.exe'}),
            },
        ]

        duplicates = review.find_bucket_duplicates([local], official)

        self.assertEqual(len(duplicates), 1)
        matches = duplicates[0]['matches']
        self.assertEqual([match['name'] for match in matches], ['other-tool', 'tool'])
        self.assertFalse(matches[0]['strong'])
        self.assertTrue(matches[1]['strong'])
        self.assertIn('download URL', matches[1]['reasons'])

    def test_report_explains_strong_and_possible_matches(self):
        local = {
            'name': 'tool',
            'path': review.Path('bucket/tool.json'),
        }
        report = review.format_report(
            [local],
            [{
                'local': local,
                'matches': [
                    {
                        'name': 'tool',
                        'repository': 'https://github.com/ScoopInstaller/Main',
                        'file_path': 'bucket/tool.json',
                        'reasons': ['download URL'],
                        'strong': True,
                        'signal_error': '',
                    },
                    {
                        'name': 'other-tool',
                        'repository': 'https://github.com/ScoopInstaller/Extras',
                        'file_path': 'bucket/other-tool.json',
                        'reasons': ['binary name'],
                        'strong': False,
                        'signal_error': '',
                    },
                ],
            }],
        )

        self.assertIn('Official package matches: **2** (**1** strong, **1** possible)', report)
        self.assertIn('**strong duplicate evidence**', report)
        self.assertIn('**possible overlap**', report)


if __name__ == '__main__':
    unittest.main()
