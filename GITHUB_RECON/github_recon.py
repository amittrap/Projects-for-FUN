"""
GitHub Secret Leak Finder

This script:
- Uses the GitHub Code Search API to find files related to a target keyword/domain.
- Downloads file contents from GitHub.
- Scans them line-by-line to detect leaked secrets such as:
  password, token, sql_credentials, ip_address, private_key, other.
- Outputs structured JSON with:
  repo name, file path, file type, line number, leaked line, match type,
  GitHub URL (with #L<line>), searched keyword, timestamp.

Usage example:

    python github_recon.py -k cashify -t YOUR_GITHUB_TOKEN

"""

import argparse
import base64
import json
import os
import re
import time
from datetime import datetime

import requests


# ==============================
# Secret Detectors
# ==============================

def line_has_target_context(line: str, keyword: str, file_path: str | None = None) -> bool:
    """
    Check if the line OR the file path contains the keyword.
    This ties the leak to the target (cashify, cashify.in, virustotal, etc.).
    """
    keyword = keyword.lower()
    if keyword in line.lower():
        return True
    if file_path and keyword in file_path.lower():
        return True
    return False


def detect_ip_address(line: str) -> bool:
    """
    Detect internal / config-style IP leaks.
    A real IP leak should:
    - Contain an IP address
    - AND be part of an assignment (= or :)
    - AND be from a private/internal range:
        10.x.x.x
        172.16.x.x – 172.31.x.x
        192.168.x.x
    This prevents public DNS zone records (like godaddy.txt) from being flagged.
    """
    # Must look like config, not a DNS zone record or plain list
    if "=" not in line and ":" not in line:
        return False

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    m = re.search(ip_pattern, line)
    if not m:
        return False

    ip = m.group(0)
    try:
        o1, o2, o3, o4 = map(int, ip.split("."))
    except ValueError:
        return False

    # Only consider private ranges as leakage
    is_private = (
        o1 == 10 or
        (o1 == 172 and 16 <= o2 <= 31) or
        (o1 == 192 and o2 == 168)
    )

    return is_private


def detect_private_key(line: str) -> bool:
    """
    Detect private key markers.
    """
    upper = line.upper()
    return (
        "BEGIN PRIVATE KEY" in upper
        or "RSA PRIVATE KEY" in upper
        or "OPENSSH PRIVATE KEY" in upper
        or "DSA PRIVATE KEY" in upper
    )


def detect_password(line: str) -> bool:
    """
    Detect password-like assignments.
    Must contain a password keyword AND an assignment (: or =).
    """
    line_l = line.lower()
    keywords = ["password", "passwd", "pwd", "admin_password", "db_password"]
    if not any(k in line_l for k in keywords):
        return False
    return ("=" in line) or (":" in line)


def detect_token(line: str) -> bool:
    """
    Detect token / auth secrets.

    Rules:
    - Line contains token-related keyword AND an assignment with a non-trivial value
      OR
    - Contains something that looks like a JWT (header.payload.signature).
    """
    line_l = line.lower()
    token_keywords = ["token", "auth_token", "access_token", "api_token", "bearer", "authorization"]

    # Case 1: keyword + assignment with long-ish value
    if any(k in line_l for k in token_keywords):
        # something like: token = "abcd1234xyz..."
        if re.search(r'[:=]\s*["\']?[A-Za-z0-9_\-\.]{10,}', line):
            return True

    # Case 2: JWT-like token (header.payload.signature)
    jwt_pattern = r'eyJ[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]{5,}\.[a-zA-Z0-9_\-]{5,}'
    if re.search(jwt_pattern, line):
        return True

    return False


def detect_sql_credentials(line: str) -> bool:
    """
    Detect SQL / DB connection info.
    Examples:
    - jdbc:mysql://user:pass@host:3306/db
    - postgresql://user:pass@db:5432/dbname
    - DB_USER / DB_PASSWORD / DB_HOST style.
    """
    line_l = line.lower()
    sql_keywords = [
        "jdbc:", "mysql:", "postgresql:", "sqlserver:",
        "db_user", "db_username", "db_password", "db_host", "db_name"
    ]
    if any(k in line_l for k in sql_keywords):
        return True

    # generic user:pass@host pattern in URLs
    if re.search(r"[A-Za-z0-9_\-]+:[^@\s]+@[A-Za-z0-9_\-\.]+", line):
        return True

    return False


def looks_like_secret_other(line: str) -> bool:
    """
    For 'other' category: generic secrets, encryption keys, internal creds.
    Must contain '=' or ':' AND a secret-like keyword AND some non-trivial value.
    """
    line_l = line.lower()
    generic_secret_keywords = [
        "secret", "client_secret", "app_secret", "encryption_key",
        "signing_key", "hmac_key", "jwt_secret", "smtp_user", "smtp_pass",
        "internal_host", "internal_server", "api_key"
    ]

    if not (("=" in line) or (":" in line)):
        return False

    if not any(k in line_l for k in generic_secret_keywords):
        return False

    # ensure there's some non-trivial value after assignment
    if re.search(r'[:=]\s*["\']?.{6,}', line):
        return True

    return False


def classify_secret_line(line: str, keyword: str, file_path: str | None = None) -> str | None:
    """
    Classify a line into one of:
        password, token, sql_credentials, ip_address, private_key, other
    or return None if it doesn't look like a leak OR isn't tied to the target.
    """

    # Only consider lines related to the target (line or file path)
    if not line_has_target_context(line, keyword, file_path):
        return None

    # Then check categories in order of specificity
    if detect_password(line):
        return "password"

    if detect_token(line):
        return "token"

    if detect_sql_credentials(line):
        return "sql_credentials"

    if detect_ip_address(line):
        return "ip_address"

    if detect_private_key(line):
        return "private_key"

    if looks_like_secret_other(line):
        return "other"

    return None


# ==============================
# GitHub API Helpers
# ==============================

GITHUB_SEARCH_API = "https://api.github.com/search/code"


def build_search_query(keyword: str) -> str:
    """
    Build GitHub search query:
    - Focus on sensitive file types
    - Search for the given keyword
    """

    sensitive_ext = [
        "env", "config", "json", "yaml", "yml", "ini",
        "xml", "py", "js", "ts", "properties", "txt",
        "sh", "cfg", "conf"
    ]

    ext_filters = " ".join([f"extension:{e}" for e in sensitive_ext])

    return f'"{keyword}" in:file {ext_filters}'


def github_search_files(keyword: str, token: str, max_pages: int = 5):
    """
    Use GitHub Code Search API to find files containing keyword.
    Returns raw GitHub items (metadata).
    """

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}",
        "User-Agent": "Secret-Leak-Finder"
    }

    query = build_search_query(keyword)
    per_page = 50

    all_items = []

    for page in range(1, max_pages + 1):

        params = {"q": query, "per_page": per_page, "page": page}

        print(f"🔍 Searching page {page}...")

        try:
            response = requests.get(GITHUB_SEARCH_API, headers=headers, params=params, timeout=15)
        except requests.exceptions.RequestException as e:
            print(f"❌ Request error on page {page}: {e}")
            break

        if response.status_code == 403:
            print("⛔ Rate limit hit. Try again with a better token or wait.")
            break

        if response.status_code == 401:
            print("❌ Invalid GitHub token (401 Unauthorized).")
            break

        if response.status_code != 200:
            print(f"❌ GitHub API error {response.status_code}: {response.text}")
            break

        result = response.json()
        items = result.get("items", [])

        if not items:
            print("ℹ️ No more results.")
            break

        all_items.extend(items)

        time.sleep(1)  # avoid fast rate hits

    return all_items


def fetch_file_content(api_url: str, token: str) -> str | None:
    """
    Fetch file content using the file's GitHub API endpoint.
    Decodes base64 content and returns full plaintext.
    """

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}",
        "User-Agent": "Secret-Leak-Finder"
    }

    try:
        response = requests.get(api_url, headers=headers, timeout=15)
    except requests.exceptions.RequestException:
        return None

    if response.status_code != 200:
        return None

    data = response.json()

    if "content" not in data:
        return None

    try:
        decoded = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return decoded
    except Exception:
        return None


def get_candidate_files(keyword: str, token: str, max_pages: int = 5):
    """
    Full pipeline:
    1. Search for matching files
    2. Fetch content for each file
    3. Return structured objects ready for line-by-line scanning
    """

    items = github_search_files(keyword, token, max_pages)
    print(f"📁 Found {len(items)} potential files.")

    candidate_files = []

    for item in items:
        api_url = item.get("url")
        file_path = item.get("path")
        html_url = item.get("html_url")
        repo_name = item.get("repository", {}).get("full_name", "")

        if not api_url:
            continue

        content = fetch_file_content(api_url, token)
        if not content:
            continue

        candidate_files.append({
            "repo_full_name": repo_name,
            "file_path": file_path,
            "html_url": html_url,
            "api_url": api_url,
            "content": content
        })

    print(f"📄 Downloaded content for {len(candidate_files)} files.")

    return candidate_files


# ==============================
# Utils
# ==============================

def get_timestamp() -> str:
    """
    Returns current time in ISO 8601 format with Z (UTC).
    Example: 2025-11-21T10:30:00Z
    """
    return datetime.utcnow().isoformat() + "Z"


def get_file_type(path: str) -> str:
    """
    Extract file extension (.env, .json, .py etc.)
    """
    if "." in path:
        return "." + path.split(".")[-1]
    return ""


def build_github_line_url(html_url: str, line_number: int) -> str:
    """
    Convert GitHub file URL into a line-anchored URL.
    Example:
      original: https://github.com/user/repo/blob/main/config.py
      output:   https://github.com/user/repo/blob/main/config.py#L42
    """
    return f"{html_url}#L{line_number}"


def build_output_record(
    repo_full_name: str,
    file_path: str,
    file_type: str,
    line_number: int,
    leaked_value: str,
    match_type: str,
    html_url: str,
    keyword: str,
    timestamp: str,
):
    """
    Build the final JSON object for results.json
    """

    return {
        "repo_full_name": repo_full_name,
        "file_path": file_path,
        "file_type": file_type,
        "line_number": line_number,
        "leaked_value": leaked_value,
        "match_type": match_type,
        "html_url": build_github_line_url(html_url, line_number),
        "searched_keyword": keyword,
        "timestamp": timestamp
    }


def save_results(results: list, output_file: str):
    """
    Save final findings list to results.json.
    Creates the directory if missing.
    """

    output_dir = os.path.dirname(output_file) or "."

    os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n💾 Results saved to: {output_file}")


# ==============================
# Scanning & CLI
# ==============================

def scan_for_leaks(files: list, keyword: str):
    """
    Scan through candidate files and detect leaked secrets line-by-line.
    De-duplication is added to prevent repeated identical leak entries.
    """
    results = []
    timestamp = get_timestamp()
    seen = set()  # to de-duplicate identical leak lines

    for file in files:
        repo_name = file["repo_full_name"]
        file_path = file["file_path"]
        html_url = file["html_url"]
        content = file["content"]
        file_type = get_file_type(file_path)

        lines = content.split("\n")

        for line_number, line in enumerate(lines, start=1):
            match_type = classify_secret_line(line, keyword, file_path=file_path)
            if match_type is None:
                continue

            leaked_value = line.strip()
            dedup_key = (repo_name, file_path, leaked_value, match_type)

            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            record = build_output_record(
                repo_full_name=repo_name,
                file_path=file_path,
                file_type=file_type,
                line_number=line_number,
                leaked_value=leaked_value,
                match_type=match_type,
                html_url=html_url,
                keyword=keyword,
                timestamp=timestamp
            )

            results.append(record)

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="GitHub Secret Leak Finder — scans GitHub for leaked credentials related to a target keyword."
    )

    parser.add_argument(
        "-k", "--keyword",
        required=True,
        help="Target keyword or domain (e.g., cashify, cashify.in, virustotal)"
    )

    parser.add_argument(
        "-t", "--token",
        required=True,
        help="GitHub Personal Access Token (PAT)"
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output file path (if not provided, uses output/results_<keyword>.json)"
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=5,
        help="Number of pages to fetch from GitHub Search API (default: 5)"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    keyword = args.keyword
    token = args.token
    output_file = args.output
    max_pages = args.max_pages

    # If user did not provide -o/--output, build a filename based on keyword
    if output_file is None:
        safe_keyword = re.sub(r"[^a-zA-Z0-9]+", "_", keyword.lower()).strip("_") or "results"
        output_file = f"output/results_{safe_keyword}.json"

    print(f"\n🔎 Starting scan for: {keyword}")
    print(f"Results will be saved to: {output_file}")
    print("Fetching candidate files from GitHub...")

    files = get_candidate_files(keyword, token, max_pages)

    if not files:
        print("❌ No files found. Exiting.")
        save_results([], output_file)
        return

    print("Scanning files for leaked secrets...")

    results = scan_for_leaks(files, keyword)

    if results:
        save_results(results, output_file)
        print(f"\n✅ Scan complete! Found {len(results)} leaked secrets.")
    else:
        print("⚠️ No leaked secrets detected.")
        save_results([], output_file)


if __name__ == "__main__":
    main()
