import subprocess
import sys
import re
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET
import sys
sys.path.append(str(Path(__file__).parent.parent))
from src.config import PROJECT_SOURCE_CODE_DIR

def run_codeql_query(db_path, query_path):
    try:
        subprocess.run(
            ["codeql", "query", "run", "--database", str(db_path), 
             "--output=results.bqrs", str(query_path)],
            check=True, capture_output=True, text=True
        )
        result = subprocess.run(
            ["codeql", "bqrs", "decode", "--format=csv", "results.bqrs"],
            capture_output=True, text=True, check=True
        )
        packages = set()
        rows = result.stdout.strip().split("\n")[1:]
        for line in rows:
            parts = line.split(",")
            if len(parts) >= 1:
                pkg_name = parts[0].strip().strip('"')
                packages.add(pkg_name)
        return packages
    except subprocess.CalledProcessError as e:
        print(f"Error running CodeQL command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return set()

def find_maven_group_id(project_dir):
    pom_paths = [
        Path(project_dir) / "pom.xml",
    ]
    
    for pom_path in pom_paths:
        if pom_path.exists():
            try:
                tree = ET.parse(pom_path)
                root = tree.getroot()
                
                ns = {'mvn': re.findall(r'{(.*)}', root.tag)[0]} if '{' in root.tag else {}
                
                if ns:
                    group_id = root.find('./mvn:groupId', ns)
                else:
                    group_id = root.find('./groupId')
                
                if group_id is not None:
                    return group_id.text
                
                if ns:
                    parent = root.find('./mvn:parent', ns)
                    if parent is not None:
                        group_id = parent.find('./mvn:groupId', ns)
                else:
                    parent = root.find('./parent')
                    if parent is not None:
                        group_id = parent.find('./groupId')
                        
                if group_id is not None:
                    return group_id.text
                    
            except Exception as e:
                print(f"Error parsing pom.xml: {e}")
    
    return None

def find_gradle_group_id(project_dir):
    gradle_paths = [
        Path(project_dir) / "build.gradle",
        Path(project_dir) / "build.gradle.kts",
    ]
    
    for gradle_path in gradle_paths:
        if gradle_path.exists():
            try:
                with open(gradle_path, 'r') as f:
                    content = f.read()
                    
                match = re.search(r'group\s*=\s*[\'"]([^\'"]+)[\'"]', content)
                if match:
                    return match.group(1)
                    
                match = re.search(r'group\s*=\s*"([^"]+)"', content)
                if match:
                    return match.group(1)
                    
            except Exception as e:
                print(f"Error parsing Gradle file: {e}")
    
    return None

def filter_internal_packages(packages, internal_package):
    internal_packages = []
    
    for pkg_name in packages:
        if pkg_name.startswith(internal_package):
            internal_packages += [pkg_name]
    
    return internal_packages

def main():
    parser = argparse.ArgumentParser(description="Extract internal packages from a Java project")
    parser.add_argument("project_name", help="Name of the project")
    parser.add_argument("--internal-package", help="Base package name for internal packages (e.g., 'org.keycloak')")
    
    args = parser.parse_args()
    project_name = args.project_name
    internal_package = args.internal_package
    
    iris_root = Path(__file__).parent.parent
    output_file = iris_root / "data" / "package-names" / f"{project_name}.txt"
    query_path = iris_root / "scripts" / "codeql-queries" / "packages.ql"
    db_path = iris_root / "data" / "codeql-dbs" / project_name
    project_path = Path(PROJECT_SOURCE_CODE_DIR) / project_name
    
    if not internal_package:
        print("Internal package not specified, trying to detect from build files...")
        
        internal_package = find_maven_group_id(project_path)
        if internal_package:
            print(f"Found Maven groupId: {internal_package}")
        else:
            internal_package = find_gradle_group_id(project_path)
            if internal_package:
                print(f"Found Gradle group: {internal_package}")
    
    if not internal_package:
        print("Error: Could not detect internal package name.")
        print("Please specify it with --internal-package (e.g., --internal-package org.keycloak)")
        sys.exit(1) 
    
    print(f"Running CodeQL query for all packages in {project_name}...")
    all_packages = run_codeql_query(db_path, query_path)
    if not all_packages:
        print("No packages found or CodeQL query failed.")
        return
    print(f"Found {len(all_packages)} total packages.")
    
    internal_packages = filter_internal_packages(all_packages, internal_package)
    excluded_packages = [pkg for pkg in all_packages if pkg not in internal_packages]
    print("Excluded packages:", excluded_packages)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w") as f:
        for package in sorted(internal_packages):
            f.write(f"{package}\n")
    
    print(f"Results written to {output_file}")
    
    Path("results.bqrs").unlink(missing_ok=True)

if __name__ == "__main__":
    main()
