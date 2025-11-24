import csv
import os
import argparse
import subprocess
from pathlib import Path
import sys
import json
sys.path.append(str(Path(__file__).parent.parent))

from src.config import CODEQL_DB_PATH, PROJECT_SOURCE_CODE_DIR, IRIS_ROOT_DIR, BUILD_INFO, DEP_CONFIGS, DATA_DIR, CODEQL_DIR, CVES_MAPPED_W_COMMITS_DIR
from scripts.docker_utils import ensure_image, create_container, exec_in_container, parse_project_image, copy_dir_to_container, copy_from_container
ALLVERSIONS = json.load(open(DEP_CONFIGS))

# Path to custom build commands CSV
BUILD_CMDS_CSV = os.path.join(DATA_DIR, "build_cmds.csv")

def load_custom_build_commands(csv_path: str = BUILD_CMDS_CSV) -> dict[str, str]:
    """
    Load custom build commands from the build command CSV file
    Returns a mapping of project_slug -> build_cmd. Missing file or invalid headers yields an empty mapping.
    """
    build_cmds: dict[str, str] = {}
    if not os.path.exists(csv_path):
        return build_cmds
    with open(csv_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            slug = (row.get("project_slug") or "").strip()
            cmd = (row.get("build_cmd") or "").strip()
            if slug and cmd:
                build_cmds[slug] = cmd
    return build_cmds

# Custom build commands for the CodeQL database creation (loaded from CSV)
CUSTOM_BUILD_COMMANDS: dict[str, str] = load_custom_build_commands()

def setup_environment(row):
    env = os.environ.copy()
    
    # Set Maven path
    mvn_version = row.get('mvn_version', 'n/a')
    if mvn_version != 'n/a':
        MAVEN_PATH = ALLVERSIONS['mvn'].get(mvn_version, None)
        if MAVEN_PATH:
            env['PATH'] = f"{os.path.join(MAVEN_PATH, 'bin')}:{env.get('PATH', '')}"
            print(f"Maven path set to: {MAVEN_PATH}")

    # Set Gradle path
    gradle_version = row.get('gradle_version', 'n/a')
    if gradle_version != 'n/a':
        GRADLE_PATH = ALLVERSIONS['gradle'].get(gradle_version, None)
        if GRADLE_PATH:
            env['PATH'] = f"{os.path.join(GRADLE_PATH, 'bin')}:{env.get('PATH', '')}"
            print(f"Gradle path set to: {GRADLE_PATH}")

    # Find and set Java home
    java_version = row['jdk_version']
    java_home = ALLVERSIONS['jdks'].get(java_version, None)
    if not java_home:
        raise Exception(f"Java version {java_version} not found in available installations.")

    env['JAVA_HOME'] = java_home
    print(f"JAVA_HOME set to: {java_home}")
    
    # Add Java binary to PATH
    env['PATH'] = f"{os.path.join(java_home, 'bin')}:{env.get('PATH', '')}"
    
    return env

def create_codeql_database(project_slug, env, db_base_path, sources_base_path):
    print("\nEnvironment variables for CodeQL database creation:")
    print(f"PATH: {env.get('PATH', 'Not set')}")
    print(f"JAVA_HOME: {env.get('JAVA_HOME', 'Not set')}")
    
    # Prefer custom build command when available
    custom_cmd = CUSTOM_BUILD_COMMANDS.get(project_slug)
    
    try:
        java_version = subprocess.check_output(['java', '-version'], 
                                            stderr=subprocess.STDOUT, 
                                            env=env).decode()
        print(f"\nJava version check:\n{java_version}")
    except subprocess.CalledProcessError as e:
        print(f"Error checking Java version: {e}")
        raise
    
    database_path = os.path.abspath(os.path.join(db_base_path, project_slug))
    source_path = os.path.abspath(os.path.join(sources_base_path, project_slug))
    
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    
    command = [
        "codeql", "database", "create",
        database_path,
        "--source-root", source_path,
        "--language", "java",
        "--overwrite",
    ]
    if custom_cmd:
        print(f"Using custom build command for {project_slug}: {custom_cmd}")
        command.extend(["--command", custom_cmd])
    
    try:
        print(f"Creating database at: {database_path}")
        print(f"Using source path: {source_path}")
        print(f"Using JAVA_HOME: {env.get('JAVA_HOME', 'Not set')}")
        res=subprocess.run(command, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode != 0:
            print(f"Error creating CodeQL database: {res.stderr.decode()} \n {res.stdout.decode()}")
            raise subprocess.CalledProcessError(res.returncode, command, output=res.stdout, stderr=res.stderr)
        print(f"Successfully created CodeQL database for {project_slug}")
    except subprocess.CalledProcessError as e:
        print(f"Error creating CodeQL database for {project_slug}: {e}")
        print(f'\nStdout Info:\n{e.stdout.decode()}')
        print(f'Stderr Info:\n{e.stderr.decode()}')
        raise


def create_codeql_database_in_container(project_slug: str, row: dict, db_base_path: str, verbose: bool = False) -> None:
    image = parse_project_image(project_slug)  # Parse the project image from the project slug
    ensure_image(image)

    # Add -docker suffix to database name when using container
    db_project_slug = f"{project_slug}-docker"

    # Prepare host and container paths
    host_db_dir = os.path.abspath(db_base_path)  # Create the host database directory
    os.makedirs(host_db_dir, exist_ok=True)
    container_codeql_dir = "/codeql"
    container_codeql_bin = f"{container_codeql_dir}/codeql"
    container_out_base = "/out"
    container_db_dir = f"{container_out_base}/{db_project_slug}"
    container_source_root = "/workspace/repo"

    # Read repo info from project_info.csv
    def get_repo_info_from_project_info(slug: str) -> tuple[str, str]:
        with open(CVES_MAPPED_W_COMMITS_DIR, 'r') as f:
            reader = csv.reader(f)
            next(reader, None)  # header
            for line in reader:
                if len(line) > 10 and line[1] == slug:
                    repo_url = line[8]
                    commit_id = line[10]
                    return repo_url, commit_id
        raise RuntimeError(f"Project slug '{slug}' not found in project_info.csv")

    container = create_container(image=image, working_dir=container_source_root)
    try:
        container.start()
        
        # Copy CodeQL CLI into container and ensure out dir exists
        copy_dir_to_container(container, CODEQL_DIR, container_codeql_dir)
        exec_in_container(container, ["bash", "-lc", f"mkdir -p {container_out_base}"])

        # Fresh fetch like fetch_one.py: reclone at desired commit
        repo_url, commit_id = get_repo_info_from_project_info(project_slug)
        fetch_cmd = (
            f"rm -rf repo && mkdir -p repo && cd repo && "
            f"git init && git remote add origin '{repo_url}' && "
            f"git fetch --no-tags --depth 1 origin {commit_id} && "
            f"git reset --hard FETCH_HEAD && "
            f"git fetch --no-tags --depth 1 origin '+refs/heads/*:refs/remotes/origin/*'"
        )
        print(f"Refreshing sources from {repo_url} @ {commit_id}")
        code, output = exec_in_container(
            container,
            ["bash", "-lc", fetch_cmd],
            workdir="/workspace",
            stream=verbose,
        )
        if code != 0:
            if output:
                print(output)
            raise RuntimeError(f"Failed to fetch sources for {project_slug}")

        # Apply project patch if available (mirror fetch_one.py behavior)
        patch_dir_host = os.path.join(DATA_DIR, "patches")
        patch_file_host = os.path.join(patch_dir_host, f"{project_slug}.patch")
        if os.path.exists(patch_file_host):
            print(f"Found patch for {project_slug}, applying...")
            # Copy entire patches dir to container to keep logic simple
            copy_dir_to_container(container, patch_dir_host, "/patches")
            code, output = exec_in_container(
                container,
                ["bash", "-lc", f"git apply /patches/{project_slug}.patch"],
                workdir=container_source_root,
                stream=verbose,
            )
            if code != 0:
                if output:
                    print(output)
                raise RuntimeError(f"Failed to apply patch for {project_slug}")
        else:
            print("No patch found; skipping patching.")

        # Prefer custom build command when available
        custom_cmd = CUSTOM_BUILD_COMMANDS.get(project_slug)
        if custom_cmd:
            print(f"Using custom build command for {project_slug}: {custom_cmd}")
            codeql_cmd = (f"{container_codeql_bin} database create {container_db_dir} "
                          f"--source-root {container_source_root} --language java --overwrite "
                          f"--command \"{custom_cmd}\"")
        else:
            codeql_cmd = (f"{container_codeql_bin} database create {container_db_dir} --source-root {container_source_root} --language java --overwrite")

        print(f"Initializing database at {container_db_dir}.")
        code, output = exec_in_container(container, ["bash", "-lc", codeql_cmd], workdir=container_source_root, stream=verbose)
        
        if code != 0:
            print(f"CodeQL database creation failed for {project_slug}")
            if not verbose and output:
                print("Error output:")
                print(output)
            raise RuntimeError(f"CodeQL database creation failed in container for {project_slug}")
        
        print(f"Finalizing database at {container_db_dir}.")
        # Copy database back to host  
        copy_from_container(container, container_db_dir, host_db_dir)
        print(f"Successfully created database at {host_db_dir}/{db_project_slug}.")
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass

def main():
    parser = argparse.ArgumentParser(description='Create CodeQL databases for cwe-bench-java projects')
    parser.add_argument('--project', help='Specific project slug', default=None)
    parser.add_argument('--db-path', help='Base path for storing CodeQL databases', default=CODEQL_DB_PATH)
    parser.add_argument('--sources-path', help='Base path for project sources', default=PROJECT_SOURCE_CODE_DIR)
    parser.add_argument('--use-container', action='store_true', help='Create DB inside the project container using mounted CodeQL')
    parser.add_argument('--verbose', action='store_true', help='Show verbose output during database creation')
    args = parser.parse_args()

    # Load build information
    projects = load_build_info()

    if args.project:
        project = next((p for p in projects if p['project_slug'] == args.project), None)
        if project:
            if args.use_container:
                create_codeql_database_in_container(project['project_slug'], project, args.db_path, args.verbose)
            else:
                env = setup_environment(project)
                create_codeql_database(project['project_slug'], env, args.db_path, args.sources_path)
        else:
            print(f"Project {args.project} not found in CSV file")
    else:
        for project in projects:
            if args.use_container:
                create_codeql_database_in_container(project['project_slug'], project, args.db_path, args.verbose)
            else:
                env = setup_environment(project)
                create_codeql_database(project['project_slug'], env, args.db_path, args.sources_path)

# Location of build_info_local.csv file
LOCAL_BUILD_INFO = os.path.join(DATA_DIR, "build-info", "build_info_local.csv")

def load_build_info():
    """
    Merge the local and global build information. Prioritize local build info.
    """
    build_info = {}

    # Get the local build info
    if os.path.exists(LOCAL_BUILD_INFO):
        with open(LOCAL_BUILD_INFO, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("status", "success") == "success":
                    build_info[row["project_slug"]] = row

    # Add the global build info if there is not local information
    with open(BUILD_INFO, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("status", "success") != "success":
                continue
            if row["project_slug"] not in build_info:
                build_info[row["project_slug"]] = row

    return list(build_info.values())

if __name__ == "__main__":
    main()
