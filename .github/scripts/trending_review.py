#!/usr/bin/env python3
"""
Trending Review for ns0m Scoop bucket.
Reviews GitHub Trending repositories for systems/app languages (Rust, Go, Zig, C, C++, C#).
Order of operations:
1. Scrape trending, load local manifest signals, and check official index/manifests for possible overlaps.
2. Qualify candidates; suppress only strong duplicate evidence and retain weaker matches as review hints.
3. Create dedicated GitHub Issues per newly qualified candidate (or display locally).
"""

import os
import sys

# Prevent Python from writing .pyc files or __pycache__ folders
sys.dont_write_bytecode = True

import argparse
import datetime
import json
import re
import subprocess
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit

DEFAULT_LANGUAGES = "rust,go,zig,c,c++,c#"
SCOOP_SEARCH_URL = "https://scoopsearch.search.windows.net/indexes/apps/docs/search?api-version=2020-06-30"
# Public read-only key used by scoop.sh's frontend.
SCOOP_SEARCH_KEY = "DC6D2BBE65FC7313F2C52BBD2B0286ED"
SCOOP_SEARCH_BATCH_SIZE = 50

# Regex patterns to detect Windows release assets (prevent matching darwin/darwin-x64)
WINDOWS_PATTERNS = [
    r'(?<![a-zA-Z])(?:windows|win64|win32|win-x64|win-arm64|x86_64-pc-windows|i686-pc-windows|aarch64-pc-windows|x86_64-w64-mingw32)(?![a-zA-Z])',
    r'(?<![a-zA-Z])win(?:32|64)?(?![a-zA-Z])',
    r'[-_]win\.',
    r'\.exe$',
    r'\.msi$'
]

# Excluded asset extensions (checksums, signatures, Linux/macOS only files)
EXCLUDED_EXTENSIONS = (
    '.sha256', '.sha512', '.sha1', '.md5', '.asc', '.sig',
    '.sbom.json', '.txt', '.pub', '.deb', '.rpm', '.apk', '.AppImage',
    '.dmg', '.pkg'
)

# Topics indicating libraries, docs, or non-installable projects
EXCLUDED_TOPICS = {
    'library', 'lib', 'framework', 'sdk', 'awesome', 'awesome-list',
    'tutorial', 'book', 'documentation', 'learn', 'cheat-sheet', 'algorithm',
    'template', 'starter', 'boilerplate', 'dataset', 'spec'
}

RATE_LIMIT_WARNED = False

def print_alert(message):
    print(flush=True)
    print(f"[!] {message}\n", file=sys.stderr, flush=True)

def warn_github_rate_limit():
    global RATE_LIMIT_WARNED
    if not RATE_LIMIT_WARNED:
        print_alert("The unauthenticated GitHub API quota (60 requests/hour) may have been exceeded. GITHUB_TOKEN is optional and increases the quota.")
        RATE_LIMIT_WARNED = True

def get_headers(token=None, github_api=False):
    headers = {
        'User-Agent': 'ns0m-ScoopTrendingReview/2.0'
    }
    if github_api:
        headers['Accept'] = 'application/vnd.github.v3+json'
        gh_token = token or os.getenv('GITHUB_TOKEN') or os.getenv('GH_TOKEN')
        if gh_token:
            headers['Authorization'] = f"Bearer {gh_token}"
    return headers

def http_get(url, token=None, github_api=False):
    req = urllib.request.Request(url, headers=get_headers(token, github_api))
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode('utf-8')

def http_get_json(url, token=None, github_api=False):
    return json.loads(http_get(url, token, github_api))

def encode_lang_slug(lang):
    return lang.strip().lower().replace('#', '%23').replace('+', '%2B')

def format_relative_date(iso_str):
    if not iso_str:
        return "Not specified"
    try:
        normalized_date = iso_str[:-1] + '+00:00' if iso_str.endswith('Z') else iso_str
        dt = datetime.datetime.fromisoformat(normalized_date)
        now = datetime.datetime.now(datetime.UTC)
        diff = now - dt
        days = diff.days
        date_str = dt.strftime("%Y-%m-%d")

        if days < 0:
            return date_str
        elif days == 0:
            rel = "today"
        elif days == 1:
            rel = "yesterday"
        elif days < 30:
            rel = f"{days} days ago"
        elif days < 365:
            months = max(1, days // 30)
            rel = f"{months} month{'s' if months > 1 else ''} ago"
        else:
            years = days // 365
            rel = f"{years} year{'s' if years > 1 else ''} ago"

        return f"{date_str} ({rel})"
    except (ValueError, TypeError, OverflowError):
        return iso_str[:10]

def scrape_trending(language, since="weekly"):
    slug = encode_lang_slug(language)
    url = f"https://github.com/trending/{slug}?since={since}"
    try:
        html = http_get(url)
        articles = re.findall(r'<article class="Box-row">(.*?)</article>', html, re.DOTALL)
        results = []
        for art in articles:
            repo_m = re.search(r'<h2 class="h3 lh-condensed">\s*<a[^>]*href="/([^"/]+/[^"/]+)"', art)
            if not repo_m:
                continue
            repo_name = repo_m.group(1).strip()
            delta_m = re.search(r'([\d,]+)\s+stars\s+(today|this week|this month)', art)
            trending_delta = f"+{delta_m.group(1)} stars {delta_m.group(2)}" if delta_m else "Trending"
            results.append({
                'repo': repo_name,
                'trending_delta': trending_delta
            })
        return results
    except (OSError, UnicodeError, ValueError) as e:
        print_alert(f"Warning: failed to scrape trending for {language}: {e}")
        return []

def get_local_manifests(bucket_dir="bucket"):
    manifests = {}
    bpath = Path(bucket_dir)
    if not bpath.exists():
        return manifests

    for file in bpath.glob("*.json"):
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
            manifests[file.stem.lower()] = get_manifest_signals(data)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, AttributeError) as e:
            print_alert(f"Could not inspect local manifest {file}: {e}")
    return manifests

def normalize_package_name(name):
    return re.sub(r'[^a-z0-9]', '', name.lower())

def get_candidate_package_names(repo_full_name):
    repo_slug = repo_full_name.rsplit('/', 1)[-1].lower()
    return {repo_slug, normalize_package_name(repo_slug)} - {''}

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
        match_filter = " or ".join(filters)
        payload = {
            "search": "*",
            "filter": f"Metadata/OfficialRepositoryNumber eq 1 and ({match_filter})",
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
        except Exception as e:
            raise RuntimeError(f"Could not query the official Scoop index: {e}") from e

        # Index matches are hints unless both the manifest name and source repository agree.
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
    asset_urls = {
        normalize_download_url(asset.get('url', ''))
        for asset in candidate.get('win_assets', [])
    } - {''}
    asset_hashes = set()
    asset_names = set()
    for asset in candidate.get('win_assets', []):
        digest = re.search(r'\b[0-9a-f]{64}\b', asset.get('digest') or '', re.IGNORECASE)
        if digest:
            asset_hashes.add(digest.group(0).lower())
        asset_names.add((asset.get('name') or '').replace('\\', '/').rsplit('/', 1)[-1].lower())

    evidence = {}
    candidate_names = {
        normalize_package_name(name)
        for name in candidate.get('package_names', {candidate['name']})
    }
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
            manifest_evidence = find_manifest_duplicate_evidence(
                candidate,
                {manifest['name']: manifest['signals']}
            )
            reasons.update(manifest_evidence.get(manifest['name'], set()))
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

def get_latest_release(repo_full_name, token=None):
    url = f"https://api.github.com/repos/{repo_full_name}/releases?per_page=1"
    req = urllib.request.Request(url, headers=get_headers(token, github_api=True))
    with urllib.request.urlopen(req, timeout=10) as resp:
        releases = json.loads(resp.read().decode('utf-8'))
        link_header = resp.headers.get('Link', '')
        match = re.search(r'[?&]page=(\d+)[^>]*>;\s*rel="last"', link_header)
        total = int(match.group(1)) if match else len(releases)
        latest = releases[0] if releases else None

    if latest and latest.get('prerelease'):
        try:
            latest = http_get_json(f"https://api.github.com/repos/{repo_full_name}/releases/latest", token, github_api=True)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                latest = None
            else:
                raise

    return latest, total

def check_english_support(repo_full_name, desc):
    """
    Verifies that the repository is in English or provides an English variant/documentation,
    conforming to official Scoop inclusion criteria ('English interface or at least English documentation').
    """
    cjk_chars = re.findall(r'[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]', desc)
    # If description has no non-Latin CJK characters, it's considered English
    if not cjk_chars:
        return True, "Description is in English"

    # If description has CJK, check for explicit English README variants
    variants = [
        "README_en.md", "README.en.md", "README-en.md", "README_EN.md",
        "README-EN.md", "readme_en.md", "readme.en.md", "docs/en/README.md",
        "README_en.rst", "README.en.rst"
    ]
    for branch in ("main", "master"):
        for v in variants:
            url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/{v}"
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                resp = urllib.request.urlopen(req, timeout=3)
                if resp.status == 200:
                    return True, f"English README variant found ({v})"
            except (OSError, urllib.error.URLError, UnicodeError):
                pass

    # Also check the default README.md
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/README.md"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=3)
            if resp.status == 200:
                content = resp.read().decode('utf-8', errors='ignore')[:1500]
                # Look for English version links
                if re.search(r'\b(English|English documentation|English README|Translation)\b', content, re.IGNORECASE):
                    return True, "README links to an English version or documentation"
                # Check ratio of Latin words to CJK in header of README
                latin_words = len(re.findall(r'[a-zA-Z]{3,}', content[:500]))
                cjk_in_readme = len(re.findall(r'[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]', content[:500]))
                if latin_words > 20 and latin_words > cjk_in_readme:
                    return True, "Main README appears to be in English"
        except (OSError, urllib.error.URLError, UnicodeError):
            pass

    return False, "Project has no English interface or documentation (does not meet official Scoop criteria)"

def evaluate_trending_repo(repo_full_name, trending_delta, token=None):
    """
    Qualify a candidate and collect its available Windows release-asset signals.
    """
    owner, repo = repo_full_name.split('/')
    candidate_slug = re.sub(r'[^a-z0-9_-]', '', repo.lower())

    # Fast skip: check latest release (saves GitHub API quota)
    try:
        rel, total_releases = get_latest_release(repo_full_name, token)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, "No GitHub release found"
        if e.code == 403:
            warn_github_rate_limit()
            return None, "GitHub API quota exceeded (token is optional)"
        return None, f"Release HTTP error {e.code}"
    except (OSError, ValueError, TypeError) as e:
        return None, f"Release error: {e}"

    if rel is None:
        return None, "No GitHub release found"

    if rel.get('prerelease', False):
        return None, "Latest release is marked as a prerelease"

    tag = rel.get('tag_name', '')
    published_at = rel.get('published_at', '')
    assets = rel.get('assets', [])
    win_assets = []
    for a in assets:
        aname = a.get('name', '')
        if aname.endswith(EXCLUDED_EXTENSIONS):
            continue
        # Reject explicit non-windows assets
        if any(bad in aname.lower() for bad in ('darwin', 'apple', 'linux', 'android', 'freebsd')):
            continue
        if any(re.search(pat, aname, re.IGNORECASE) for pat in WINDOWS_PATTERNS):
            win_assets.append({
                'name': aname,
                'url': a.get('browser_download_url', ''),
                'size': a.get('size', 0),
                'digest': a.get('digest', '')
            })

    if not win_assets:
        return None, f"No Windows binary in release ({len(assets)} assets)"

    # Metadata & topic inspection
    api_url = f"https://api.github.com/repos/{repo_full_name}"
    try:
        info = http_get_json(api_url, token, github_api=True)
    except urllib.error.HTTPError as e:
        if e.code == 403:
            warn_github_rate_limit()
        return None, f"Metadata error: {e}"
    except (OSError, ValueError, TypeError) as e:
        return None, f"Metadata error: {e}"

    if info.get('archived') or info.get('disabled'):
        return None, "Repository is archived or disabled"

    topics = [t.lower() for t in info.get('topics', [])]
    if any(t in EXCLUDED_TOPICS for t in topics):
        return None, f"Excluded topic: {set(topics) & EXCLUDED_TOPICS}"

    desc = (info.get('description') or '').strip()
    if re.search(r'\b(library|framework|sdk|crate for|bindings for|collection of|curated list|cheat-sheet)\b', desc, re.IGNORECASE):
        return None, "Description indicates a library, framework, or list"

    # Language check (conforming to official Scoop criteria: English interface or at least English docs)
    is_en, en_reason = check_english_support(repo_full_name, desc)
    if not is_en:
        return None, en_reason

    # Classify CLI vs GUI
    is_gui = False
    if any(a['name'].endswith('.msi') or 'setup' in a['name'].lower() for a in win_assets) or any(k in desc.lower() for k in ('desktop', 'gui', 'electron', 'tauri', 'interface graph', 'wpf', 'winui', 'avalonia')) or 'gui' in topics or 'desktop-app' in topics:
        is_gui = True

    app_type = "GUI" if is_gui else "CLI"

    # Clean version
    clean_ver = tag.lstrip('v')
    if clean_ver.startswith(f"{repo}-v"):
        clean_ver = clean_ver[len(f"{repo}-v"):]
    elif clean_ver.startswith(f"{repo}-"):
        clean_ver = clean_ver[len(f"{repo}-"):]

    return {
        'repo': repo_full_name,
        'owner': owner,
        'repo_name': repo,
        'name': candidate_slug,
        'tag': tag,
        'version': clean_ver,
        'description': desc,
        'homepage': info.get('homepage') or info.get('html_url'),
        'stars': info.get('stargazers_count', 0),
        'forks': info.get('forks_count', 0),
        'open_issues': info.get('open_issues_count', 0),
        'created_at': info.get('created_at', ''),
        'pushed_at': info.get('pushed_at', ''),
        'published_at': published_at,
        'total_releases': total_releases,
        'trending_delta': trending_delta,
        'license': (info.get('license') or {}).get('spdx_id', 'Not specified'),
        'type': app_type,
        'win_assets': win_assets
    }, "OK"

def collect_existing_issue_keys(issues):
    seen_repos = set()
    seen_names = set()
    seen_pairs = set()
    issue_by_pair = {}
    for iss in issues:
        body = iss.get('body') or ''
        title = iss.get('title') or ''
        issue_repos = set()
        for match in re.findall(
            r'github\.com/([^/\s\)\"\']+/[^/\s\)\"\']+)',
            body + " " + title,
            re.IGNORECASE
        ):
            repo = normalize_github_repo(match)
            if repo:
                seen_repos.add(repo)
                issue_repos.add(repo)
        issue_text = title + "\n" + body
        issue_names = set()
        for match in re.findall(
            r'\[(?:Candidate|Request)\]:\s*([a-z0-9_-]+)|Candidate:\s*`([^`]+)`',
            issue_text,
            re.IGNORECASE
        ):
            normalized = normalize_package_name(match[0] or match[1])
            if normalized:
                seen_names.add(normalized)
                issue_names.add(normalized)
        issue = {
            'number': iss.get('number'),
            'state': iss.get('state', 'UNKNOWN').lower(),
            'url': iss.get('url', ''),
        }
        for pair in ((repo, name) for repo in issue_repos for name in issue_names):
            seen_pairs.add(pair)
            issue_by_pair.setdefault(pair, []).append(issue)
    return seen_repos, seen_names, seen_pairs, issue_by_pair

def get_existing_issues():
    cmd = ["gh", "issue", "list", "--state", "all", "--limit", "1000", "--json", "title,body,number,state,url"]
    try:
        res = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except OSError as e:
        raise RuntimeError(f"Could not run gh issue list: {e}") from e
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip() or "gh issue list failed")
    try:
        issues = json.loads(res.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Could not parse existing issues: {e}") from e

    return collect_existing_issue_keys(issues)

def filter_existing_issue_candidates(candidates, existing_pairs, seen_repos, seen_names):
    remaining = []
    for candidate in candidates:
        repo = normalize_github_repo(candidate['repo'])
        name = normalize_package_name(candidate['name'])
        issues = existing_pairs.get((repo, name))
        if issues:
            details = ', '.join(
                f"{issue['state']} issue #{issue['number']} {issue['url']}".strip()
                for issue in issues
            )
            print(f"      skipped · existing {details} | {candidate['repo']}")
            continue
        if repo in seen_repos:
            candidate['duplicate_hints'].append(
                "An existing issue references this repository under a different candidate name."
            )
        if name in seen_names:
            candidate['duplicate_hints'].append(
                "An existing issue uses this normalized candidate name for another or unknown repository."
            )
        remaining.append(candidate)
    return remaining

def get_candidate_metadata(candidate):
    repo = candidate['repo']
    homepage = candidate.get('homepage')
    homepage_parts = urlsplit(homepage) if homepage else None
    metadata = {
        "Repository": f"https://github.com/{repo}",
        "Trending when detected": candidate['trending_delta'],
        "Stars": f"{candidate['stars']:,}",
        "Forks": f"{candidate['forks']:,}",
        "Open issues": f"{candidate['open_issues']:,}",
        "Releases": candidate['total_releases'],
        "Latest release": f"{candidate['tag']} ({candidate['version']})",
        "Published": format_relative_date(candidate['published_at']),
        "Created": format_relative_date(candidate['created_at']),
        "Last git activity": format_relative_date(candidate['pushed_at']),
        "License": candidate['license'],
    }
    if homepage and not (
        homepage_parts.hostname
        and homepage_parts.hostname.lower() in {'github.com', 'www.github.com'}
        and homepage_parts.path.strip('/').lower() == repo.lower()
    ):
        metadata["Official website"] = homepage
    return metadata

def format_candidate_metadata(candidate):
    m = get_candidate_metadata(candidate)
    lines = [f"- **Repository**: {m['Repository']}"]
    if "Official website" in m:
        lines.append(f"- **Official website**: {m['Official website']}")
    lines.extend([
        f"- **Trending when detected**: :fire: `{m['Trending when detected']}`",
        f"- **Stars**: :star: **{m['Stars']}**",
        f"- **Forks**: :fork_and_knife: **{m['Forks']}**",
        f"- **Open issues**: :warning: **{m['Open issues']}**",
        f"- **Releases**: :label: **{m['Releases']}** published releases",
        f"- **Latest release**: `{m['Latest release']}`, published **{m['Published']}**",
        f"- **Project age**: Created **{m['Created']}** *(last git activity: {m['Last git activity']})*",
        f"- **License**: `{m['License']}`",
    ])
    return lines

def create_candidate_issue(candidate, lang):
    name = candidate['name']
    app_type = candidate['type']
    desc = candidate['description'] or "No description provided."
    title = f"[Candidate]: {name} ({app_type}) - {desc[:60].strip()}"

    body_lines = [
        f"### :package: Candidate: `{name}` ({app_type})",
        "",
        f"> {desc}",
        "",
        f"Found on **GitHub Trending ({lang.upper()})**.",
        "",
        "#### :bar_chart: Metadata & popularity",
    ]
    body_lines.extend(format_candidate_metadata(candidate))
    body_lines.extend([
        "",
        "#### :floppy_disk: Detected Windows binaries",
    ])
    for asset in candidate['win_assets'][:6]:
        size_mb = f"{asset['size'] / (1024 * 1024):.1f} MB" if asset['size'] else "size not specified"
        digest = f"; `{asset['digest']}`" if asset.get('digest') else ""
        body_lines.append(f"- [`{asset['name']}`]({asset['url']}) ({size_mb}{digest})")
    if candidate.get('duplicate_hints'):
        body_lines.extend([
            "",
            "Potential overlap signals from automated input checks (investigate; these are not definitive duplicates):",
        ])
        body_lines.extend(f"- {hint}" for hint in candidate['duplicate_hints'])

    body = "\n".join(body_lines)

    labels = "package-request,trending-candidate"
    cmd = ["gh", "issue", "create", "--title", title, "--body", body, "--label", labels]
    res = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if res.returncode == 0:
        issue_url = res.stdout.strip()
        print(f"[+] Created Issue: {issue_url}")
        return issue_url
    else:
        cmd_fallback = ["gh", "issue", "create", "--title", title, "--body", body]
        res2 = subprocess.run(cmd_fallback, check=False, capture_output=True, text=True)
        if res2.returncode == 0:
            issue_url = res2.stdout.strip()
            print(f"[+] Created Issue (no labels): {issue_url}")
            return issue_url
        print(f"[!] Failed to create issue: {res2.stderr}", file=sys.stderr)
        return None

def run_tests():
    suite = unittest.defaultTestLoader.discover(
        str(Path(__file__).parent),
        pattern='test_trending_review.py'
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1

def main():
    parser = argparse.ArgumentParser(description="Review GitHub Trending for the ns0m Scoop bucket")
    parser.add_argument("--languages", default=os.getenv("TRENDING_LANGUAGES", DEFAULT_LANGUAGES), help="Comma-separated languages")
    parser.add_argument("--since", default=os.getenv("TRENDING_SINCE", "weekly"), help="Trending period: daily, weekly, or monthly")
    parser.add_argument("--max-issues", type=int, default=int(os.getenv("MAX_ISSUES", "5")), help="Maximum number of issues to open per run")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--local", action="store_true", help="Local mode: print results without creating GitHub issues")
    mode.add_argument("--test", action="store_true", help="Run offline duplicate-detection tests")
    parser.add_argument("--output", help="Optional path for the Markdown report")
    args = parser.parse_args()

    if args.test:
        return run_tests()

    languages = [l.strip() for l in args.languages.split(",") if l.strip()]
    print("=== Revue Trending Scoop ===")
    print(f"Languages: {languages} (period: {args.since})")

    # Step 1: gather local and official manifest signals before qualification.
    print("\n[1/2] Reviewing GitHub Trending...")
    local_manifests = get_local_manifests("bucket")

    final_candidates = []
    seen_repos = set()
    seen_candidate_names = {}

    for lang in languages:
        print(f"\n      {lang} — scraping trending repositories...")
        trending_items = scrape_trending(lang, args.since)
        pending_candidates = []
        for item in trending_items:
            repo_name = item['repo']
            normalized_repo = normalize_github_repo(repo_name)
            if normalized_repo in seen_repos:
                continue
            seen_repos.add(normalized_repo)

            package_names = get_candidate_package_names(repo_name)
            pending_candidates.append({
                'repo': repo_name,
                'language': lang,
                'trending_delta': item['trending_delta'],
                'package_names': package_names
            })

        if not pending_candidates:
            print(f"      {lang} — no repositories found.")
            continue

        print(f"      {lang} — checking buckets and qualifying candidates...")
        try:
            official_manifests = find_official_manifests(pending_candidates)
        except RuntimeError as e:
            print_alert(f"Could not verify Scoop buckets: {e}")
            return 1

        for item in pending_candidates:
            repo_name = item['repo']
            data, _ = evaluate_trending_repo(repo_name, item['trending_delta'])
            if data:
                data['language'] = lang
                data['package_names'] = item['package_names']
                data['duplicate_hints'] = []
                local_evidence = find_manifest_duplicate_evidence(data, local_manifests)
                official_evidence = find_official_duplicate_evidence(data, official_manifests)
                strong_local = {
                    name: reasons for name, reasons in local_evidence.items()
                    if has_strong_duplicate_evidence({name: reasons})
                }
                strong_official = {
                    key: reasons for key, reasons in official_evidence.items()
                    if has_strong_duplicate_evidence({key: reasons})
                }
                if strong_local or strong_official:
                    locations = []
                    locations.extend(
                        f"ns0m bucket (manifest '{name}': {', '.join(sorted(reasons))})"
                        for name, reasons in strong_local.items()
                    )
                    for (name, repository, _), reasons in strong_official.items():
                        locations.append(
                            f"{get_bucket_name(repository)} bucket "
                            f"(manifest '{name}': {', '.join(sorted(reasons))})"
                        )
                    print(
                        f"      skipped · found in {', '.join(locations)} | {repo_name}"
                    )
                    continue

                for manifest_name, reasons in local_evidence.items():
                    data['duplicate_hints'].append(
                        f"Local manifest '{manifest_name}' shares: {', '.join(sorted(reasons))}."
                    )
                for manifest in official_manifests:
                    key = (manifest['name'], manifest['repository'], manifest['homepage'])
                    reasons = official_evidence.get(key)
                    if reasons:
                        unavailable = (
                            f" Detailed manifest signals unavailable: {manifest['signal_error']}."
                            if manifest.get('signal_error') else ""
                        )
                        data['duplicate_hints'].append(
                            f"Official manifest '{manifest['name']}' "
                            f"({manifest['repository']}) shares: {', '.join(sorted(reasons))}."
                            f"{unavailable}"
                        )

                candidate_name = normalize_package_name(data['name'])
                previous_candidates = seen_candidate_names.setdefault(candidate_name, [])
                for previous in previous_candidates:
                    if previous['repo'] == data['repo']:
                        continue
                    data['duplicate_hints'].append(
                        f"Trending repository shares a normalized name with {previous['repo']}."
                    )
                    previous['duplicate_hints'].append(
                        f"Trending repository shares a normalized name with {data['repo']}."
                    )
                previous_candidates.append(data)
                final_candidates.append(data)
                print(
                    f"      candidate · input checks passed; duplicate review pending | "
                    f"{repo_name} | {data['type']} | v{data['version']} | {item['trending_delta']}"
                )

    print(f"\n[summary] Candidates passing input checks (duplicate review pending): {len(final_candidates)}")

    # Step 2: process candidates (create issues or display locally).
    print("\n[2/2] Processing candidates...")
    if final_candidates:
        try:
            seen_issue_repos, seen_issue_names, seen_issue_pairs, issue_by_pair = get_existing_issues()
        except RuntimeError as e:
            print_alert(f"Could not verify existing repository issues; refusing to report or create unchecked candidates: {e}")
            return 1
        print(f"      Existing issues checked (open and closed): {len(seen_issue_pairs)} candidate pairs.")
        final_candidates = filter_existing_issue_candidates(
            final_candidates, issue_by_pair, seen_issue_repos, seen_issue_names
        )

    if not args.local and os.getenv("GITHUB_ACTIONS"):
        issues_created = 0
        for c in final_candidates:
            if issues_created >= args.max_issues:
                print_alert(f"Maximum issue limit reached ({args.max_issues}). Remaining candidates will be processed in a future run.")
                break

            issue_url = create_candidate_issue(c, c['language'])
            if issue_url:
                issues_created += 1
        print(f"[+] Done. Created {issues_created} new issue(s).")
    else:
        # Sortie locale
        print("\n=== Candidates passing input checks (local mode; duplicate review pending) ===\n")
        lines = []
        for c in final_candidates:
            metadata = dict(get_candidate_metadata(c))
            desc = c['description'] or "No description provided."
            report_lines = [
                (
                    f"- [{c['name']}] ({c['type']}, {c['language']}) - "
                    f"[{c['repo']}]({metadata['Repository']}) (v{c['version']})"
                ),
                f"  > {desc}",
            ]
            if "Official website" in metadata:
                report_lines.append(f"  Official website: {metadata['Official website']}")
            if c.get('duplicate_hints'):
                report_lines.append(
                    "  Potential duplicate signals: " + "; ".join(c['duplicate_hints'])
                )
            report_lines.extend([
                (
                    f"  Trending: {metadata['Trending when detected']} | "
                    f"Stars: {metadata['Stars']} | Forks: {metadata['Forks']}"
                ),
                (
                    f"  Releases: {metadata['Releases']} | Latest release: {metadata['Latest release']}, "
                    f"published {metadata['Published']} | Created: {metadata['Created']}"
                ),
                "",
            ])
            report = "\n".join(report_lines)
            lines.append(report)
            print(report)

        if args.output:
            Path(args.output).write_text("\n".join(lines), encoding="utf-8")
            print(f"[+] Report written to {args.output}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
