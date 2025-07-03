import csv
import os
import argparse
import subprocess
from pathlib import Path
import sys
import json
sys.path.append(str(Path(__file__).parent.parent))

from src.config import CODEQL_DB_PATH, PROJECT_SOURCE_CODE_DIR, IRIS_ROOT_DIR, BUILD_INFO, DEP_CONFIGS, DATA_DIR
ALLVERSIONS = json.load(open(DEP_CONFIGS))

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
        "--overwrite"
    ]
    
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

def main():
    parser = argparse.ArgumentParser(description='Create CodeQL databases for cwe-bench-java projects')
    parser.add_argument('--project', help='Specific project slug', default=None)
    parser.add_argument('--db-path', help='Base path for storing CodeQL databases', default=CODEQL_DB_PATH)
    parser.add_argument('--sources-path', help='Base path for project sources', default=PROJECT_SOURCE_CODE_DIR)
    args = parser.parse_args()

    # Load build information
    projects = load_build_info()

    if args.project:
        project = next((p for p in projects if p['project_slug'] == args.project), None)
        if project:
            env = setup_environment(project)
            create_codeql_database(project['project_slug'], env, args.db_path, args.sources_path)
        else:
            print(f"Project {args.project} not found in CSV file")
    else:
        for project in projects:
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
