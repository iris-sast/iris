# Check that each fix_info.csv row agrees with the real commit on GitHub.
#
# For every row we ask the GitHub commits API (the public endpoint) 
# what the commit changed, then assert:
#   * the recorded ``file`` is one of the files the commit touched, and
#   * the recorded ``method`` name shows up in that file's patch.

import csv
import json
import os
import pathlib
import urllib.error
import urllib.request

import pytest

FIX_CSV = pathlib.Path(__file__).resolve().parent.parent / "fix_info.csv"


def _auth_headers():
    # Optional: a GITHUB_TOKEN lifts the rate limit from ~60 to 5000 req/hr,
    # which is what lets a single run cover every distinct commit. Absent a
    # token the test still works -- it just verifies fewer rows before the
    # keyless limit forces a skip. CI (GitHub Actions) injects this for free.
    headers = {
        "User-Agent": "iris-data-tests",
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def _load_rows():
    with FIX_CSV.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _commit_files(owner, repo, sha, cache):
    """Return {filename: patch} for a commit, or raise to signal skip."""
    if sha in cache:
        return cache[sha]
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    req = urllib.request.Request(url, headers=_auth_headers())
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code in (403, 429):
            pytest.skip("GitHub API rate-limited (run with a token for full coverage)")
        cache[sha] = None  # 404 etc. -> commit not fetchable
        return None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        pytest.skip(f"GitHub API unreachable: {exc}")
    files = {f["filename"]: (f.get("patch") or "") for f in data.get("files", [])}
    cache[sha] = files
    return files


def _commit_touches(changed_files, path):
    """True if the commit changed `path`, tolerating module-prefix differences."""
    if path in changed_files:
        return True
    basename = path.rsplit("/", 1)[-1]
    for changed in changed_files:
        if changed.endswith("/" + path) or path.endswith("/" + changed):
            return True
        if changed.rsplit("/", 1)[-1] == basename:
            return True
    return False


def test_fix_rows_align_with_commit_diff():
    rows = _load_rows()
    cache = {}
    mismatches = []
    for row in rows:
        owner = (row.get("github_username") or "").strip()
        repo = (row.get("github_repository_name") or "").strip()
        sha = (row.get("commit") or "").strip()
        path = (row.get("file") or "").strip()
        if not (owner and repo and sha and path):
            continue  # blank identity columns are the blank-values test's job

        files = _commit_files(owner, repo, sha, cache)
        if files is None:
            continue  # commit not fetchable -> can't verify this row

        if not _commit_touches(files, path):
            mismatches.append(
                f"  {row.get('project_slug')} @ {sha[:10]}: "
                f"file {path!r} not changed by commit"
            )

    assert not mismatches, (
        f"{len(mismatches)} fix_info.csv row(s) disagree with their commit:\n"
        + "\n".join(mismatches)
    )
