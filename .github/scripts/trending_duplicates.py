"""Duplicate signals from local and official Scoop manifests."""

import json
import re
import sys
import urllib.request
from urllib.parse import quote, urlsplit

SCOOP_SEARCH_URL = "https://scoopsearch.search.windows.net/indexes/apps/docs/search?api-version=2020-06-30"
# Public read-only key used by scoop.sh's frontend.
SCOOP_SEARCH_KEY = "DC6D2BBE65FC7313F2C52BBD2B0286ED"
SCOOP_SEARCH_BATCH_SIZE = 50


def print_alert(message):
    print(flush=True)
    print(f"[!] {message}\n", file=sys.stderr, flush=True)


def normalize_package_name(name):
    return re.sub(r'[^a-z0-9]', '', name.lower())


def get_candidate_package_names(repo_full_name):
    owner, _, repo_slug = repo_full_name.lower().partition('/')
    names = {repo_slug, normalize_package_name(repo_slug)}
    if owner and repo_slug:
        names.add(f'{owner}-{repo_slug}')
        names.add(normalize_package_name(f'{owner}{repo_slug}'))
    return names - {''}


def normalize_github_repo(value):
    value = (value or '').strip().rstrip('.,);]')
    match = re.search(
        r'(?:https?://)?(?:www\.)?github\.com/([^/\s?#]+)/([^/\s?#]+)'
        r'|^([^/\s?#]+)/([^/\s?#]+)$',
        value,
        re.IGNORECASE
    )
    if not match:
        return ''
    owner, repo = match.group(1, 2) if match.group(1) else match.group(3, 4)
    return f"{owner.lower()}/{repo.lower().removesuffix('.git')}"


def get_bucket_name(repository):
    repo = normalize_github_repo(repository)
    if not repo:
        return repository or "unknown"
    return repo.rsplit('/', 1)[-1].removesuffix('.git').lower()


def normalize_download_url(value):
    value = (value or '').split('#', 1)[0].strip()
    if not value:
        return ''
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value.rstrip('/')
    return parts._replace(
        scheme=parts.scheme.lower(),
        netloc=parts.netloc.lower()
    ).geturl().rstrip('/')


def collect_binary_names(value):
    if isinstance(value, str):
        candidate = value.strip().split('|', 1)[0].strip()
        return {candidate.replace('\\', '/').rsplit('/', 1)[-1].lower()} if candidate.lower().endswith('.exe') else set()
    if isinstance(value, (list, tuple)):
        return set().union(*(collect_binary_names(item) for item in value))
    if isinstance(value, dict):
        return set().union(*(collect_binary_names(item) for item in value.values()))
    return set()


def get_manifest_signals(data):
    checkver = data.get('checkver', {})
    homepage = data.get('homepage', '')
    urls = set()
    hashes = set()

    def collect(section):
        if isinstance(section, dict):
            for key, value in section.items():
                if key == 'url':
                    urls.update(
                        normalize_download_url(item)
                        for item in (value if isinstance(value, list) else [value])
                        if isinstance(item, str) and normalize_download_url(item)
                    )
                elif key == 'hash':
                    for item in value if isinstance(value, list) else [value]:
                        match = re.search(r'\b[0-9a-f]{64}\b', item, re.IGNORECASE) if isinstance(item, str) else None
                        if match:
                            hashes.add(match.group(0).lower())
                elif key != 'checkver':
                    collect(value)
        elif isinstance(section, list):
            for item in section:
                collect(item)

    collect(data)
    checkver_repo = normalize_github_repo(checkver.get('github', '')) if isinstance(checkver, dict) else ''
    homepage_repo = normalize_github_repo(homepage)
    return {
        'repos': {repo for repo in (checkver_repo, homepage_repo) if repo},
        'homepage': homepage,
        'homepage_repo': homepage_repo,
        'urls': urls,
        'hashes': hashes,
        'bins': collect_binary_names((data.get('bin'), data.get('shortcuts'))),
    }


def find_official_manifests(candidates):
    candidate_names = set().union(*(item['package_names'] for item in candidates))
    candidate_repos = {
        normalize_github_repo(item['repo']) for item in candidates
    } - {''}
    normalized_names = {normalize_package_name(name) for name in candidate_names} - {''}
    search_names = sorted(candidate_names | normalized_names)
    repo_filter = " or ".join(
        f"Homepage eq '{scheme}://{host}/{owner}/{name}{suffix}'"
        for owner, name in (repo.split('/', 1) for repo in candidate_repos)
        for scheme in ('https', 'http')
        for host in ('github.com', 'www.github.com')
        for suffix in ('', '/')
    )

    matches = {}
    for offset in range(0, len(search_names), SCOOP_SEARCH_BATCH_SIZE):
        batch = search_names[offset:offset + SCOOP_SEARCH_BATCH_SIZE]
        filters = [
            "search.ismatch('{}', 'Name', 'full', 'all')".format(name.replace("'", "''"))
            for name in batch
        ]
        if repo_filter:
            filters.append(repo_filter)
        payload = {
            "search": "*",
            "filter": (
                "Metadata/OfficialRepositoryNumber eq 1 and "
                f"({' or '.join(filters)})"
            ),
            "top": 1000,
            "select": "Name,Homepage,Metadata/Repository,Metadata/BranchName,Metadata/FilePath"
        }
        request = urllib.request.Request(
            SCOOP_SEARCH_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'User-Agent': 'ns0m-ScoopTrendingReview/2.0',
                'api-key': SCOOP_SEARCH_KEY,
                'Content-Type': 'application/json'
            },
            method='POST'
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode('utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as e:
            raise RuntimeError(f"Could not query the official Scoop index: {e}") from e

        for item in data.get('value', []):
            name = normalize_package_name(item.get('Name', ''))
            homepage_repo = normalize_github_repo(item.get('Homepage', ''))
            if name not in normalized_names and homepage_repo not in candidate_repos:
                continue
            repository = item.get('Metadata', {}).get('Repository')
            if not repository:
                raise RuntimeError(f"Official manifest '{name}' has no repository listed in the Scoop index")
            repository = repository.rstrip('/')
            key = (item.get('Name', ''), repository, item.get('Homepage', ''))
            if key in matches:
                continue
            manifest = {
                'name': item.get('Name', ''),
                'repository': repository,
                'homepage': item.get('Homepage', ''),
                'homepage_repo': homepage_repo,
            }
            metadata = item.get('Metadata', {})
            try:
                manifest['signals'] = fetch_official_manifest_signals(
                    repository,
                    metadata.get('BranchName', ''),
                    metadata.get('FilePath', '')
                )
            except (OSError, UnicodeError, ValueError, TypeError, AttributeError) as e:
                manifest['signal_error'] = str(e)
                print_alert(
                    f"Could not inspect official manifest '{manifest['name']}' "
                    f"from {manifest['repository']}: {e}"
                )
            matches[key] = manifest

    return list(matches.values())


def fetch_official_manifest_signals(repository, branch, file_path):
    repo = normalize_github_repo(repository)
    if not repo or not branch or not file_path:
        raise ValueError("the Scoop index did not provide a GitHub repository, branch, and manifest path")
    raw_url = (
        f"https://raw.githubusercontent.com/{repo}/"
        f"{quote(branch, safe='')}/{quote(file_path, safe='/')}"
    )
    request = urllib.request.Request(
        raw_url,
        headers={'User-Agent': 'ns0m-ScoopTrendingReview/2.0'}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        data = json.loads(response.read().decode('utf-8'))
    if not isinstance(data, dict):
        raise TypeError("manifest content is not a JSON object")
    return get_manifest_signals(data)


def find_manifest_duplicate_evidence(candidate, manifests):
    repo = normalize_github_repo(candidate['repo'])
    homepage = candidate.get('homepage', '')
    assets = candidate.get('win_assets', [])
    asset_urls = {
        normalize_download_url(asset.get('url', '')) for asset in assets
    } - {''}
    asset_hashes = {
        match.group(0).lower()
        for asset in assets
        if (match := re.search(r'\b[0-9a-f]{64}\b', asset.get('digest') or '', re.IGNORECASE))
    }
    asset_names = {
        (asset.get('name') or '').replace('\\', '/').rsplit('/', 1)[-1].lower()
        for asset in assets
    }
    candidate_names = {
        normalize_package_name(name)
        for name in candidate.get('package_names', {candidate['name']})
    }

    evidence = {}
    for name, signals in manifests.items():
        reasons = set()
        if repo and repo in signals['repos']:
            reasons.add('repository')
        if homepage and normalize_download_url(homepage) == normalize_download_url(signals['homepage']):
            reasons.add('homepage')
        if asset_urls & signals['urls']:
            reasons.add('download URL')
        if asset_hashes & signals['hashes']:
            reasons.add('SHA-256')
        if asset_names & signals['bins']:
            reasons.add('binary name')
        if normalize_package_name(name) in candidate_names:
            reasons.add('manifest name')
        if reasons:
            evidence[name] = reasons
    return evidence


def find_official_duplicate_evidence(candidate, manifests):
    repo = normalize_github_repo(candidate['repo'])
    candidate_names = {
        normalize_package_name(name)
        for name in candidate.get('package_names', {candidate['name']})
    }
    evidence = {}
    for manifest in manifests:
        reasons = set()
        if normalize_package_name(manifest['name']) in candidate_names:
            reasons.add('manifest name')
        if repo and repo == manifest['homepage_repo']:
            reasons.add('repository/homepage')
        if manifest.get('signals'):
            reasons.update(
                find_manifest_duplicate_evidence(
                    candidate,
                    {manifest['name']: manifest['signals']}
                ).get(manifest['name'], set())
            )
        if reasons:
            key = (manifest['name'], manifest['repository'], manifest['homepage'])
            evidence[key] = reasons
    return evidence


def has_strong_duplicate_evidence(evidence):
    return any(
        'download URL' in reasons
        or 'SHA-256' in reasons
        or {'repository', 'manifest name'} <= reasons
        or {'repository/homepage', 'manifest name'} <= reasons
        for reasons in evidence.values()
    )
