#!/usr/bin/env python3
"""
Trending Review for ns0m Scoop bucket.
Reviews GitHub Trending repositories for systems/app languages (Rust, Go, Zig, C, C++, C#).
Order of operations:
1. Scrape trending and apply fast local/technical filters (local bucket, releases, Windows binaries, libraries).
2. For surviving candidates, verify and filter out those already in official Scoop buckets.
3. Create dedicated GitHub Issues per newly qualified candidate (or display locally).
"""

import os
import sys

# Prevent Python from writing .pyc files or __pycache__ folders
sys.dont_write_bytecode = True

import re
import json
import subprocess
import argparse
import datetime
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from pathlib import Path

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
        dt = datetime.datetime.fromisoformat(iso_str.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
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
    except Exception:
        return iso_str[:10]

def scrape_trending(language, since="daily"):
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
    except Exception as e:
        print_alert(f"Warning: failed to scrape trending for {language}: {e}")
        return []

def get_local_manifests(bucket_dir="bucket"):
    local_pkgs = set()
    local_repos = set()
    bpath = Path(bucket_dir)
    if not bpath.exists():
        return local_pkgs, local_repos

    for file in bpath.glob("*.json"):
        pkg = file.stem.lower()
        local_pkgs.add(pkg)
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
            checkver = data.get("checkver", {})
            if isinstance(checkver, dict):
                gh = checkver.get("github", "")
                m = re.search(r'github\.com/([^/]+/[^/]+)', gh)
                if m:
                    local_repos.add(m.group(1).lower())
            hp = data.get("homepage", "")
            m_hp = re.search(r'github\.com/([^/]+/[^/]+)', hp)
            if m_hp:
                local_repos.add(m_hp.group(1).lower())
        except Exception:
            pass
    return local_pkgs, local_repos

def find_official_manifests(package_names):
    packages = {
        re.sub(r'[^a-z0-9_-]', '', name.lower())
        for name in package_names
    } - {''}
    matches = {}
    package_names = sorted(packages)

    for offset in range(0, len(package_names), SCOOP_SEARCH_BATCH_SIZE):
        batch = package_names[offset:offset + SCOOP_SEARCH_BATCH_SIZE]
        name_filter = " or ".join(
            f"search.ismatch('{name}', 'Name', 'full', 'all')"
            for name in batch
        )
        payload = {
            "search": "*",
            "filter": f"Metadata/OfficialRepositoryNumber eq 1 and ({name_filter})",
            "top": 1000,
            "select": "Name,Metadata/Repository"
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

        # Full-text matching can return token/substring matches; only exact manifest names count.
        for item in data.get('value', []):
            name = re.sub(r'[^a-z0-9_-]', '', item.get('Name', '').lower())
            if name not in batch:
                continue
            repository = item.get('Metadata', {}).get('Repository')
            if not repository:
                raise RuntimeError(f"Official manifest '{name}' has no repository listed in the Scoop index")
            matches.setdefault(name, set()).add(repository.rstrip('/'))

    return matches

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
            except Exception:
                continue

    # Also check the default README.md
    for branch in ("main", "master"):
        url = f"https://raw.githubusercontent.com/{repo_full_name}/{branch}/README.md"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=3)
            if resp.status == 200:
                content = resp.read().decode('utf-8', errors='ignore')[:1500]
                # Look for English version links
                if re.search(r'\b(English|English documentation|English README|Translation)\b', content, re.I):
                    return True, "README links to an English version or documentation"
                # Check ratio of Latin words to CJK in header of README
                latin_words = len(re.findall(r'[a-zA-Z]{3,}', content[:500]))
                cjk_in_readme = len(re.findall(r'[\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]', content[:500]))
                if latin_words > 20 and latin_words > cjk_in_readme:
                    return True, "Main README appears to be in English"
        except Exception:
            continue

    return False, "Project has no English interface or documentation (does not meet official Scoop criteria)"

def evaluate_trending_repo(repo_full_name, trending_delta, token=None):
    """
    Evaluate a repository that has already passed the local and official bucket filters.
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
    except Exception as e:
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
                'size': a.get('size', 0)
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
    except Exception as e:
        return None, f"Metadata error: {e}"

    if info.get('archived') or info.get('disabled'):
        return None, "Repository is archived or disabled"

    topics = [t.lower() for t in info.get('topics', [])]
    if any(t in EXCLUDED_TOPICS for t in topics):
        return None, f"Excluded topic: {set(topics) & EXCLUDED_TOPICS}"

    desc = (info.get('description') or '').strip()
    if re.search(r'\b(library|framework|sdk|crate for|bindings for|collection of|curated list|cheat-sheet)\b', desc, re.I):
        return None, "Description indicates a library, framework, or list"

    # Language check (conforming to official Scoop criteria: English interface or at least English docs)
    is_en, en_reason = check_english_support(repo_full_name, desc)
    if not is_en:
        return None, en_reason

    # Classify CLI vs GUI
    is_gui = False
    if any(a['name'].endswith('.msi') or 'setup' in a['name'].lower() for a in win_assets):
        is_gui = True
    elif any(k in desc.lower() for k in ('desktop', 'gui', 'electron', 'tauri', 'interface graph', 'wpf', 'winui', 'avalonia')):
        is_gui = True
    elif 'gui' in topics or 'desktop-app' in topics:
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

def get_existing_issues():
    seen_repos = set()
    seen_names = set()
    cmd = ["gh", "issue", "list", "--state", "all", "--limit", "300", "--json", "title,body,number"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            issues = json.loads(res.stdout)
            for iss in issues:
                body = iss.get('body', '')
                title = iss.get('title', '')
                for match in re.findall(r'github\.com/([^/\s\)\"\']+/[^/\s\)\"\']+)', body + " " + title):
                    seen_repos.add(match.lower())
                m_title = re.search(r'\[(?:Candidate|Request)\]:\s*([a-z0-9_-]+)', title, re.I)
                if m_title:
                    seen_names.add(m_title.group(1).lower())
    except Exception as e:
        print_alert(f"Could not check existing issues: {e}")

    return seen_repos, seen_names

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
        body_lines.append(f"- [`{asset['name']}`]({asset['url']}) ({size_mb})")

    body = "\n".join(body_lines)

    labels = "package-request,trending-candidate"
    cmd = ["gh", "issue", "create", "--title", title, "--body", body, "--label", labels]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        issue_url = res.stdout.strip()
        print(f"[+] Created Issue: {issue_url}")
        return issue_url
    else:
        cmd_fallback = ["gh", "issue", "create", "--title", title, "--body", body]
        res2 = subprocess.run(cmd_fallback, capture_output=True, text=True)
        if res2.returncode == 0:
            issue_url = res2.stdout.strip()
            print(f"[+] Created Issue (no labels): {issue_url}")
            return issue_url
        print(f"[!] Failed to create issue: {res2.stderr}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(description="Review GitHub Trending for the ns0m Scoop bucket")
    parser.add_argument("--languages", default=os.getenv("TRENDING_LANGUAGES", DEFAULT_LANGUAGES), help="Comma-separated languages")
    parser.add_argument("--since", default=os.getenv("TRENDING_SINCE", "daily"), help="Trending period: daily, weekly, or monthly")
    parser.add_argument("--max-issues", type=int, default=int(os.getenv("MAX_ISSUES", "5")), help="Maximum number of issues to open per run")
    parser.add_argument("--local", action="store_true", help="Local mode: print results without creating GitHub issues")
    parser.add_argument("--output", help="Optional path for the Markdown report")
    args = parser.parse_args()

    languages = [l.strip() for l in args.languages.split(",") if l.strip()]
    print(f"=== Revue Trending Scoop ===")
    print(f"Languages: {languages} (period: {args.since})")

    # Step 1: filter local and official bucket manifests before detailed analysis.
    print("\n[1/2] Reviewing GitHub Trending...")
    local_pkgs, local_repos = get_local_manifests("bucket")

    final_candidates = []
    seen_repos = set()

    for lang in languages:
        print(f"\n      {lang} — scraping trending repositories...")
        trending_items = scrape_trending(lang, args.since)
        pending_candidates = []
        for item in trending_items:
            repo_name = item['repo']
            if repo_name.lower() in seen_repos:
                continue
            seen_repos.add(repo_name.lower())

            candidate_slug = re.sub(r'[^a-z0-9_-]', '', repo_name.rsplit('/', 1)[-1].lower())
            repo_slug = repo_name.rsplit('/', 1)[-1].lower()
            package_names = {
                repo_slug,
                candidate_slug,
                repo_slug.replace('_', '-'),
                candidate_slug.replace('_', '-')
            }
            local_matches = package_names & local_pkgs
            if repo_name.lower() in local_repos or local_matches:
                if local_matches:
                    manifest = sorted(local_matches)[0]
                    reason = f"local manifest '{manifest}'"
                else:
                    reason = "repository already referenced"
                print(f"      skipped · ns0m bucket | {repo_name} | {reason}")
                continue

            pending_candidates.append({
                'repo': repo_name,
                'language': lang,
                'trending_delta': item['trending_delta'],
                'package_names': package_names
            })

        if not pending_candidates:
            print(f"      {lang} — no repositories left after the local filter.")
            continue

        print(f"      {lang} — checking buckets and qualifying candidates...")
        try:
            all_package_names = set().union(*(item['package_names'] for item in pending_candidates))
            official_pkgs = find_official_manifests(all_package_names)
        except RuntimeError as e:
            print_alert(f"Could not verify Scoop buckets: {e}")
            return 1

        for item in pending_candidates:
            repo_name = item['repo']
            matched_names = {
                re.sub(r'[^a-z0-9_-]', '', name.lower())
                for name in item['package_names']
            } & official_pkgs.keys()
            if matched_names:
                matched_name = sorted(matched_names)[0]
                bucket_names = sorted({
                    repository.rstrip('/').rsplit('/', 1)[-1].removesuffix('.git')
                    for repository in official_pkgs[matched_name]
                })
                print(f"      skipped · official bucket {', '.join(bucket_names)} | {repo_name} | manifest '{matched_name}'")
                continue

            data, _ = evaluate_trending_repo(repo_name, item['trending_delta'])
            if data:
                data['language'] = lang
                final_candidates.append(data)
                print(f"      kept · {repo_name} | {data['type']} | v{data['version']} | {item['trending_delta']}")

    print(f"\n[summary] Qualified candidates: {len(final_candidates)}")

    # Step 2: process candidates (create issues or display locally).
    print("\n[2/2] Processing candidates...")
    if not args.local and os.getenv("GITHUB_ACTIONS"):
        seen_issue_repos, seen_issue_names = get_existing_issues()
        print(f"      Existing issues checked: {len(seen_issue_repos)} repositories already tracked.")

        issues_created = 0
        for c in final_candidates:
            if issues_created >= args.max_issues:
                print_alert(f"Maximum issue limit reached ({args.max_issues}). Remaining candidates will be processed in a future run.")
                break

            repo_lower = c['repo'].lower()
            name_lower = c['name'].lower()

            if repo_lower in seen_issue_repos or name_lower in seen_issue_names:
                print(f"      skipped · issue already exists | {c['repo']}")
                continue

            issue_url = create_candidate_issue(c, c['language'])
            if issue_url:
                issues_created += 1
                seen_issue_repos.add(repo_lower)
                seen_issue_names.add(name_lower)
        print(f"[+] Done. Created {issues_created} new issue(s).")
    else:
        # Sortie locale
        print("\n=== Qualified candidates (local mode) ===\n")
        lines = []
        for c in final_candidates:
            metadata = dict(get_candidate_metadata(c))
            desc = c['description'] or "No description provided."
            report_lines = [
                f"- [{c['name']}] ({c['type']}, {c['language']}) - "
                f"[{c['repo']}]({metadata['Repository']}) (v{c['version']})",
                f"  > {desc}",
            ]
            if "Official website" in metadata:
                report_lines.append(f"  Official website: {metadata['Official website']}")
            report_lines.extend([
                f"  Trending: {metadata['Trending when detected']} | "
                f"Stars: {metadata['Stars']} | Forks: {metadata['Forks']}",
                f"  Releases: {metadata['Releases']} | Latest release: {metadata['Latest release']}, "
                f"published {metadata['Published']} | Created: {metadata['Created']}",
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
