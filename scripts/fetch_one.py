"""
Fetch a single project from Github and checkout the buggy commit.

Usage: python3 fetch_one.py <project_slug>

The script fetches one project from Github, checking out the buggy commit,
and then patches it with the essential information for it to be buildable.
The project is specified with the Project Slug that contains project name,
CVE ID, and version tag.

Example:
    python3 fetch_one.py apache__camel_CVE-2018-8041_2.20.3
"""

import os
import sys
import csv
import argparse
import subprocess
from pathlib import Path

# Set up import path for src
THIS_SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = THIS_SCRIPT_DIR.parent
sys.path.append(str(ROOT_DIR))

from src.config import DATA_DIR
from scripts.docker_utils import ensure_image, parse_project_image


def fetch_project(project_slug, from_container=False, verbose=False):
    """Fetch a single project either from Github (default) or from a prebuilt container image."""
    target_dir = Path(DATA_DIR) / "project-sources" / project_slug

    # Check if project already exists
    if target_dir.exists():
        print(f"[fetch_one] Skipping: {target_dir} already exists")
        return True

    if from_container:
        image = f"irissast/cwe-bench-java-containers:{project_slug}"
        print(f"[fetch_one] Pulling container image {image}...")
        try:
            if verbose:
                subprocess.run(["docker", "pull", image], check=True)
            else:
                subprocess.run(["docker", "pull", image], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            print(f"[fetch_one] Failed to pull image")
            return False

    if from_container:
        image = parse_project_image(project_slug)
        if verbose:
            print(f"[fetch_one] Ensuring container image is available: {image}")
        try:
            ensure_image(image)
        except Exception as e:
            print(f"[fetch_one] Failed to pull image {image}: {e}")
            return False
        if verbose:
            print(f"[fetch_one] Image ready: {image}")
        return True

    # Default: fetch from Github
    project_info_path = Path(DATA_DIR) / "project_info.csv"
    row = None

    # Read project information from CSV
    try:
        with open(project_info_path, newline='') as csvfile:
            reader = csv.reader(csvfile)
            for line in reader:
                if line[1] == project_slug:
                    row = line
                    break
    except FileNotFoundError:
        print(f"[fetch_one] Error: {project_info_path} not found")
        return False
    except Exception as e:
        print(f"[fetch_one] Error reading project info: {e}")
        return False

    if not row:
        print(f"[fetch_one] Project slug '{project_slug}' not found in project_info.csv")
        return False

    repo_url, commit_id = row[8], row[10]

    # Clone repository
    print(f"[fetch_one] Cloning repository from {repo_url}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(target_dir)], 
            check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[fetch_one] Failed to clone repository: {e.stderr}")
        return False

    # Fetch and checkout specific commit
    print(f"[fetch_one] Fetching and checking out commit {commit_id}...")
    try:
        subprocess.run(
            ["git", "fetch", "--depth", "1", "origin", commit_id], 
            cwd=target_dir, check=True, capture_output=True, text=True
        )
        subprocess.run(
            ["git", "checkout", commit_id], 
            cwd=target_dir, check=True, capture_output=True, text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[fetch_one] Failed to checkout commit: {e.stderr}")
        return False

    # Apply patch if available
    patch_path = Path(DATA_DIR) / "patches" / f"{project_slug}.patch"
    if patch_path.exists():
        print(f"[fetch_one] Applying patch {patch_path}...")
        try:
            subprocess.run(
                ["git", "apply", str(patch_path)], 
                cwd=target_dir, check=True, capture_output=True, text=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[fetch_one] Failed to apply patch: {e.stderr}")
            return False
    else:
        print(f"[fetch_one] No patch found; skipping patching.")

    print(f"[fetch_one] Successfully fetched {project_slug}")
    return True


def main():
    """Main function to handle argument parsing and project fetching."""
    parser = argparse.ArgumentParser(
        description="Fetch a single project from Github and checkout the buggy commit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fetch_one.py apache__camel_CVE-2018-8041_2.20.3
  python3 fetch_one.py spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE
        """
    )
    parser.add_argument(
        "project_slug", 
        type=str, 
        help="Project slug (e.g., apache__camel_CVE-2018-8041_2.20.3)"
    )
    parser.add_argument(
        "--from-container",
        action="store_true",
        help="Fetch project from prebuilt Docker image instead of Github"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Stream verbose output from subprocesses"
    )
    
    args = parser.parse_args()
    
    success = fetch_project(args.project_slug, from_container=args.from_container, verbose=args.verbose)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
