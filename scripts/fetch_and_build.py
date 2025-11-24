import os
import argparse
import csv
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up paths
THIS_SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = THIS_SCRIPT_DIR.parent
sys.path.append(str(ROOT_DIR))

# Now import from src after path is set up
from src.config import DATA_DIR

def fetch_and_build_one(payload):
    """Fetch and optionally build a single project."""
    (project, no_build, try_all, jdk, mvn, gradle, gradlew, use_container, verbose) = payload
    project_slug = project[1]
    
    print(f"== Processing {project_slug} ==")
    
    # Fetch the project
    print(f"== Fetching {project_slug} ==")
    fetch_cmd = ["python3", f"{ROOT_DIR}/scripts/fetch_one.py", project_slug]
    if use_container:
        fetch_cmd.append("--from-container")
    if verbose:
        fetch_cmd.append("--verbose")
    
    if verbose:
        result = subprocess.run(fetch_cmd)
    else:
        result = subprocess.run(fetch_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Failed to fetch {project_slug}")
        if not verbose:
            print("----- STDOUT -----")
            print(result.stdout)
            print("----- STDERR -----")
            print(result.stderr)
        return False
    
    print(f"== Done fetching {project_slug} ==")
    if no_build:
        return True
    
    # Build the project

    print(f"== Building {project_slug} ==")
    
    build_cmd = ["python3", f"{ROOT_DIR}/scripts/build_one.py", project_slug]
    if try_all:
        build_cmd.append("--try_all")
        print(f"== Building {project_slug} with try_all ==")
    if jdk:
        build_cmd.extend(["--jdk", jdk])
        print(f"== Building {project_slug} with jdk {jdk} ==")
    if mvn:
        build_cmd.extend(["--mvn", mvn])
        print(f"== Building {project_slug} with mvn {mvn} ==")
    if gradle:
        build_cmd.extend(["--gradle", gradle])
        print(f"== Building {project_slug} with gradle {gradle} ==")
    if gradlew:
        build_cmd.append("--gradlew")
        print(f"== Building {project_slug} with gradlew ==")
    if use_container:
        build_cmd.append("--use-container")
    
    if verbose:
        result = subprocess.run(build_cmd)
    else:
        result = subprocess.run(build_cmd, capture_output=True, text=True)
    
    if result.returncode != 0:
        print(f"Failed to build {project_slug}")
        if not verbose:
            print("----- STDOUT -----")
            print(result.stdout)
            print("----- STDERR -----")
            print(result.stderr)
        return False
    
    print(f"== Done fetching and building {project_slug} ==")
    return True

def parallel_fetch_and_build(projects, no_build, try_all, jdk, mvn, gradle, gradlew, use_container, verbose):
    """Process multiple projects in parallel."""
    results = []
    failed_projects = []
    
    with ThreadPoolExecutor() as executor:
        # Submit tasks for each project
        future_to_project = {
            executor.submit(fetch_and_build_one, (project, no_build, try_all, jdk, mvn, gradle, gradlew, use_container, verbose)): project 
            for project in projects
        }

        # Collect results as they complete
        for future in as_completed(future_to_project):
            project = future_to_project[future]
            project_slug = project[1]
            
            try:
                success = future.result()
                results.append(success)
                if not success:
                    failed_projects.append(project_slug)
            except Exception as exc:
                print(f'>> Project {project_slug} generated an exception: {exc}')
                failed_projects.append(project_slug)
                results.append(False)

    # Print summary
    successful = sum(results)
    total = len(projects)
    print(f"\n====== Summary ======")
    print(f"Successfully processed: {successful}/{total}")
    if failed_projects:
        print(f"Failed projects: {', '.join(failed_projects)}")

    return results

def main():
    """Main function to handle argument parsing and project processing."""
    parser = argparse.ArgumentParser(
        description="Fetch and build Java projects from the CWE benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scripts/fetch_and_build.py --no-build                    # Only fetch projects
  python3 scripts/fetch_and_build.py --filter apache               # Process only Apache projects
  python3 scripts/fetch_and_build.py --cwe CWE-022 CWE-078         # Process specific CWE types
  python3 scripts/fetch_and_build.py --exclude testng              # Exclude specific projects
  python3 scripts/fetch_and_build.py --cve CVE-2021-29425          # Process a specific CVE ID
  python3 scripts/fetch_and_build.py --jdk 11 --mvn 3.9.8          # Use specific JDK and Maven versions
        """
    )
    
    # Build control arguments
    parser.add_argument("--no-build", action="store_true", 
                       help="Only fetch projects, don't build them")
    parser.add_argument("--try_all", action="store_true",
                       help="Try all build configurations for each project")
    parser.add_argument("--use-container", action="store_true",
                       help="Fetch projects from prebuilt Docker images and skip local build")
    parser.add_argument("--verbose", action="store_true",
                       help="Stream verbose output from subprocesses")
    
    # Build configuration arguments
    parser.add_argument("--jdk", type=str, 
                       help="Specific JDK version to use (e.g., '8', '11', '17')")
    parser.add_argument("--mvn", type=str, 
                       help="Specific Maven version to use (e.g., '3.5.0', '3.9.8')")
    parser.add_argument("--gradle", type=str, 
                       help="Specific Gradle version to use (e.g., '6.8.2', '7.6.4', '8.9')")
    parser.add_argument("--gradlew", action="store_true", 
                       help="Use the project's gradlew script")
    
    # Project filtering arguments
    parser.add_argument("--filter", nargs="+", type=str,
                       help="Only process projects containing these strings")
    parser.add_argument("--exclude", nargs="+", type=str,
                       help="Exclude projects containing these strings")
    parser.add_argument("--cwe", nargs="+", type=str,
                       help="Only process projects with these CWE IDs")
    parser.add_argument("--cve", nargs="+", type=str,
                       help="Only process projects with these CVE IDs")
    parser.add_argument("--force", action="store_true",
                       help="Force processing even if projects already exist")
    
    args = parser.parse_args()
    
    # Create necessary directories
    try:
        if not args.no_build and not args.use_container:
            subprocess.run(["mkdir", "-p", f"{DATA_DIR}/build-info"], check=True)
        subprocess.run(["mkdir", "-p", f"{DATA_DIR}/project-sources"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error creating directories: {e}")
        return 1
    
    # Read project information
    try:
        with open(f"{DATA_DIR}/project_info.csv", 'r') as f:
            reader = list(csv.reader(f))[1:]  # Skip header
    except FileNotFoundError:
        print(f"Error: {DATA_DIR}/project_info.csv not found")
        return 1
    except Exception as e:
        print(f"Error reading project info: {e}")
        return 1
    
    # Filter projects based on arguments
    projects = filter_projects(reader, args)
    
    if not projects:
        print("No projects match the specified filters.")
        return 0
    
    print(f"====== Fetching and Building {len(projects)} Repositories ======")
    
    # Process projects
    results = parallel_fetch_and_build(
        projects, args.no_build, args.try_all, 
        args.jdk, args.mvn, args.gradle, args.gradlew, args.use_container, args.verbose
    )
    
    return 0 if all(results) else 1


def filter_projects(projects, args):
    """Filter projects based on command line arguments."""
    filtered_projects = []
    
    for project in projects:
        project_slug = project[1]
        project_cve_id = project[2]
        project_cwe_id = project[3]
        
        # Check CWE filter
        if args.cwe and not any(cwe == project_cwe_id for cwe in args.cwe):
            continue
        
        # Check CVE filter
        if args.cve and not any(cve == project_cve_id for cve in args.cve):
            continue
        
        # Check inclusion filter
        if args.filter and not any(f in project_slug for f in args.filter):
            continue
        
        # Check exclusion filter
        if args.exclude and any(f in project_slug for f in args.exclude):
            continue
        
        filtered_projects.append(project)
    
    return filtered_projects

if __name__ == "__main__":
    sys.exit(main())
