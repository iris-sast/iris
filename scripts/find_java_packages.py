import os
import re
import sys
from pathlib import Path

def find_java_packages(base_dir):
    packages = set()
    package_pattern = re.compile(r'^\s*package\s+([\w.]+);')
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(".java"):
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                        for line in f:
                            if match := package_pattern.match(line):
                                packages.add(match.group(1))
                                break
                except UnicodeDecodeError:
                    continue
    return sorted(packages)

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <project_name>")
        sys.exit(1)

    project_name = sys.argv[1]
    iris_root = Path(__file__).parent.parent
    project_dir = iris_root / "data" / "cwe-bench-java" / "project-sources" / project_name
    output_dir = iris_root / "data" / "cwe-bench-java" / "package-names"
    output_file = output_dir / f"{project_name}"
    
    packages = find_java_packages(str(project_dir))
    print(f"Found packages: {packages}")
    
    output_dir.mkdir(exist_ok=True)
    print(f"Writing to: {output_file}")
    
    with open(output_file, "w") as f:
        for package in packages:
            f.write(f"{package}\n")

if __name__ == "__main__":
    main()
