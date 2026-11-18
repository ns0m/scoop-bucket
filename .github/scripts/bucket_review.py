#!/usr/bin/env python3
"""Find ns0m bucket manifests that may overlap with official Scoop buckets."""

import argparse
import json
import sys
import unittest
from pathlib import Path

from trending_duplicates import (
    find_official_duplicate_evidence,
    find_official_manifests,
    get_bucket_name,
    get_candidate_package_names,
    get_manifest_signals,
    has_strong_duplicate_evidence,
    normalize_package_name,
)


def load_local_manifests(bucket_dir="bucket"):
    manifests = []
    for file in sorted(Path(bucket_dir).glob("*.json")):
        try:
            with file.open("r", encoding="utf-8") as manifest_file:
                data = json.load(manifest_file)
            if not isinstance(data, dict):
                raise TypeError("manifest is not a JSON object")
            manifests.append({
                'name': file.stem,
                'path': file,
                'signals': get_manifest_signals(data),
            })
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, AttributeError) as error:
            print(f"[!] Could not inspect local manifest {file}: {error}", file=sys.stderr)
    return manifests


def get_official_lookup_candidates(manifests):
    candidates = []
    for manifest in manifests:
        name = manifest['name']
        signals = manifest['signals']
        package_names = {name, normalize_package_name(name)}
        for repository in signals['repos']:
            candidates.append({
                'repo': repository,
                'package_names': package_names | get_candidate_package_names(repository),
            })
        if not signals['repos']:
            candidates.append({'repo': '', 'package_names': package_names})
    return candidates


def get_manifest_candidate(manifest, repo):
    signals = manifest['signals']
    assets = [{'url': url} for url in signals['urls']]
    assets.extend({'digest': digest} for digest in signals['hashes'])
    assets.extend({'name': binary} for binary in signals['bins'])
    package_names = {manifest['name'], normalize_package_name(manifest['name'])}
    if repo:
        package_names.update(get_candidate_package_names(repo))
    return {
        'repo': repo,
        'name': manifest['name'],
        'package_names': package_names,
        'homepage': signals['homepage'],
        'win_assets': assets,
    }


def find_bucket_duplicates(local_manifests, official_manifests):
    official_by_key = {
        (
            manifest['name'],
            manifest['repository'],
            manifest['homepage'],
        ): manifest
        for manifest in official_manifests
    }
    duplicates = []
    for local in local_manifests:
        evidence = {}
        repositories = sorted(local['signals']['repos']) or ['']
        for repo in repositories:
            candidate = get_manifest_candidate(local, repo)
            for key, reasons in find_official_duplicate_evidence(
                candidate, official_manifests
            ).items():
                evidence.setdefault(key, set()).update(reasons)

        if evidence:
            duplicates.append({
                'local': local,
                'matches': [
                    {
                        'name': name,
                        'repository': repository,
                        'homepage': homepage,
                        'file_path': official_by_key[
                            (name, repository, homepage)
                        ].get('file_path', ''),
                        'signal_error': official_by_key[
                            (name, repository, homepage)
                        ].get('signal_error', ''),
                        'reasons': sorted(reasons),
                        'strong': has_strong_duplicate_evidence({name: reasons}),
                    }
                    for (name, repository, homepage), reasons in sorted(evidence.items())
                ],
            })
    return duplicates


def format_report(local_manifests, duplicates):
    match_count = sum(len(duplicate['matches']) for duplicate in duplicates)
    strong_count = sum(
        match['strong']
        for duplicate in duplicates
        for match in duplicate['matches']
    )
    possible_count = sum(
        not match['strong']
        for duplicate in duplicates
        for match in duplicate['matches']
    )
    lines = [
        "# ns0m bucket duplicate review",
        "",
        f"Analyzed manifests: **{len(local_manifests)}**",
        (
            f"Local manifests with official matches: **{len(duplicates)}**. "
            f"Official package matches: **{match_count}** "
            f"(**{strong_count}** strong, **{possible_count}** possible)."
        ),
        "",
        (
            "Strong matches have matching download URLs or SHA-256 hashes, or a matching "
            "manifest name plus source repository/homepage. Other matches are review hints, "
            "not proof that the packages are interchangeable."
        ),
        "",
    ]
    if not duplicates:
        lines.append("No matches were found in the official-bucket index.")
        return "\n".join(lines)

    for duplicate in duplicates:
        local = duplicate['local']
        lines.append(f"## `{local['path'].as_posix()}`")
        for match in duplicate['matches']:
            label = "strong duplicate evidence" if match['strong'] else "possible overlap"
            bucket = get_bucket_name(match['repository'])
            manifest_path = match['file_path'] or f"bucket/{match['name']}.json"
            details = (
                f"`{match['repository']}/{manifest_path}` "
                f"({bucket}): {', '.join(match['reasons'])}"
            )
            if match['signal_error']:
                details += f"; manifest signals unavailable: {match['signal_error']}"
            lines.append(f"- **{label}** — {details}")
        lines.append("")
    return "\n".join(lines).rstrip()


def run_tests():
    suite = unittest.defaultTestLoader.discover(
        str(Path(__file__).parent),
        pattern='test_bucket_review.py',
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(
        description="Review ns0m bucket manifests against official Scoop buckets"
    )
    parser.add_argument("--bucket", default="bucket", help="Directory containing local manifests")
    parser.add_argument("--test", action="store_true", help="Run offline duplicate-detection tests")
    args = parser.parse_args()

    if args.test:
        return run_tests()

    local_manifests = load_local_manifests(args.bucket)
    if not local_manifests:
        print(f"[!] No readable manifests found in {args.bucket}", file=sys.stderr)
        return 1

    try:
        official_manifests = find_official_manifests(
            get_official_lookup_candidates(local_manifests)
        )
    except RuntimeError as error:
        print(f"[!] Could not verify official Scoop buckets: {error}", file=sys.stderr)
        return 1

    duplicates = find_bucket_duplicates(local_manifests, official_manifests)
    report = format_report(local_manifests, duplicates)
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
