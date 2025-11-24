"""
Build a single Java project with various build configurations.

Usage: python3 build_one.py <project_slug> [options]

The script attempts to build a Java project using different combinations of
JDK versions and build tools (Maven, Gradle, or gradlew). It can use predefined
configurations or custom versions specified via command line arguments.

Example:
    python3 build_one.py apache__camel_CVE-2018-8041_2.20.3
    python3 build_one.py spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE --jdk 11 --mvn 3.9.8
"""

import os
import sys
import csv
import json
import argparse
import subprocess
from datetime import datetime
from pathlib import Path

# Set up import path for src
THIS_SCRIPT_DIR = Path(__file__).parent
ROOT_DIR = THIS_SCRIPT_DIR.parent
sys.path.append(str(ROOT_DIR))

from src.config import DATA_DIR, DEP_CONFIGS
from scripts.docker_utils import create_container, ensure_image, exec_in_container, parse_project_image

# Load dependency configurations
ALLVERSIONS = json.load(open(DEP_CONFIGS))

# Predefined build attempts
ATTEMPTS = [
    {"jdk": "8", "mvn": "3.5.0"},      # Attempt 1
    {"jdk": "17", "mvn": "3.5.0"},     # Attempt 2
    {"jdk": "17", "mvn": "3.9.8"},     # Attempt 3
    {"jdk": "8", "mvn": "3.9.8"},      # Attempt 4
    {"jdk": "17", "gradle": "8.9"},    # Attempt 5
    {"jdk": "8", "gradle": "7.6.4"},   # Attempt 6
    {"jdk": "8", "gradle": "6.8.2"},   # Attempt 7
    {"jdk": "8", "gradlew": 1},        # Attempt 8
    {"jdk": "17", "gradlew": 1},       # Attempt 9
]

# Build result constants
NEWLY_BUILT = "newly-built"
ALREADY_BUILT = "already-built"
FAILED = "failed"


def is_built(project_slug):
    """Check if a project has already been built."""
    build_info_path = Path(DATA_DIR) / "build-info" / f"{project_slug}.json"
    return build_info_path.exists()


def save_build_info(project_slug, attempt):
    """Save build configuration information to JSON file."""
    build_info_path = Path(DATA_DIR) / "build-info" / f"{project_slug}.json"
    build_info_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(build_info_path, 'w') as f:
        json.dump(attempt, f, indent=2)


def save_local_build_result(project_slug, success, attempt):
    """Save build result to local CSV file for tracking."""
    build_result_path = Path(DATA_DIR) / "build-info" / "build_info_local.csv"
    build_result_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Read existing data
    rows = []
    if build_result_path.exists():
        with open(build_result_path, 'r') as f:
            reader = csv.reader(f)
            rows = list(reader)[1:]  # Skip header
    
    # Add new row
    timestamp = datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
    rows.append([
        timestamp,
        project_slug,
        "success" if success else "failure",
        attempt.get("jdk", "n/a"),
        attempt.get("mvn", "n/a"),
        attempt.get("gradle", "n/a"),
        attempt.get("gradlew", "n/a"),
    ])
    
    # Write back to file
    with open(build_result_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "project_slug", "status", "jdk_version", "mvn_version", "gradle_version", "use_gradlew"])
        writer.writerows(rows)


def get_build_info_from_csv(project_slug, csv_path):
    """Get successful build configuration from CSV file."""
    if not Path(csv_path).exists():
        return None
    
    print(f"[build_one] Checking build info from {csv_path}")
    try:
        with open(csv_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['project_slug'] == project_slug and row['status'] == 'success':
                    specific_attempt = {}
                    if row['jdk_version'] not in ('n/a', '', None):
                        specific_attempt['jdk'] = row['jdk_version']
                    if row['mvn_version'] not in ('n/a', '', None):
                        specific_attempt['mvn'] = row['mvn_version']
                    if row['gradle_version'] not in ('n/a', '', None):
                        specific_attempt['gradle'] = row['gradle_version']
                    if row['use_gradlew'] != 'n/a':
                        if row['use_gradlew'] == "True":
                            specific_attempt['gradlew'] = 1
                        else:
                            specific_attempt['gradlew'] = 0

                    # Check if we have a JDK and a build tool configuration
                    if 'jdk' in specific_attempt and any(key in specific_attempt for key in ['mvn', 'gradle', 'gradlew']):
                        print(f"[build_one] Found successful build configuration: {specific_attempt}")
                        return specific_attempt
    except Exception as e:
        print(f"[build_one] Failed to read or use build info from CSV: {str(e)}")
    
    return None


def build_with_maven(project_slug, attempt):
    """Build project using Maven."""
    target_dir = Path(DATA_DIR) / "project-sources" / project_slug
    
    jdk_version = attempt['jdk']
    mvn_version = attempt['mvn']
    
    print(f"[build_one] Building {project_slug} with Maven {mvn_version} and JDK {jdk_version}...")
    
    # Validate paths
    java_path = ALLVERSIONS["jdks"].get(jdk_version)
    maven_path = ALLVERSIONS["mvn"].get(mvn_version)
    
    if not java_path or not maven_path:
        print(f"[build_one] JDK {jdk_version} or Maven {mvn_version} not found in available installations.")
        return FAILED
    
    if not Path(java_path).exists() or not Path(maven_path).exists():
        print(f"[build_one] JDK {jdk_version} or Maven {mvn_version} not found in filesystem.")
        return FAILED
    
    if not Path(java_path, "bin", "java").exists() or not Path(maven_path, "bin", "mvn").exists():
        print(f"[build_one] JDK {jdk_version} or Maven {mvn_version} binaries not found.")
        return FAILED
    
    print(f"[build_one] JAVA_PATH: {java_path}")
    print(f"[build_one] MAVEN_PATH: {maven_path}")
    
    # Maven build command
    mvn_cmd = [
        "mvn", "clean", "package", "-B", "-V", "-e",
        "-Dfindbugs.skip", "-Dcheckstyle.skip", "-Dpmd.skip=true",
        "-Dspotbugs.skip", "-Denforcer.skip", "-Dmaven.javadoc.skip",
        "-DskipTests", "-Dmaven.test.skip.exec", "-Dlicense.skip=true",
        "-Drat.skip=true", "-Dspotless.check.skip=true"
    ]
    
    try:
        result = subprocess.run(
            mvn_cmd,
            cwd=target_dir,
            env={
                "PATH": f"{os.environ['PATH']}:{maven_path}/bin",
                "JAVA_HOME": java_path,
            },
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[build_one] Build succeeded for {project_slug} with Maven {mvn_version} and JDK {jdk_version}")
        save_build_info(project_slug, attempt)
        return NEWLY_BUILT
        
    except subprocess.CalledProcessError as e:
        print(f"[build_one] Build failed for {project_slug} with Maven {mvn_version} and JDK {jdk_version}")
        print(f"Return code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return FAILED


def build_with_gradle(project_slug, attempt):
    """Build project using Gradle."""
    target_dir = Path(DATA_DIR) / "project-sources" / project_slug
    
    jdk_version = attempt['jdk']
    gradle_version = attempt['gradle']
    
    print(f"[build_one] Building {project_slug} with Gradle {gradle_version} and JDK {jdk_version}...")
    
    # Validate paths
    java_path = ALLVERSIONS["jdks"].get(jdk_version)
    gradle_path = ALLVERSIONS["gradle"].get(gradle_version)
    
    if not java_path or not gradle_path:
        print(f"[build_one] JDK {jdk_version} or Gradle {gradle_version} not found in available installations.")
        return FAILED
    
    if not Path(java_path).exists() or not Path(gradle_path).exists():
        print(f"[build_one] JDK {jdk_version} or Gradle {gradle_version} not found in filesystem.")
        return FAILED
    
    # Gradle build command
    gradle_cmd = ["gradle", "build", "--parallel"]
    
    try:
        result = subprocess.run(
            gradle_cmd,
            cwd=target_dir,
            env={
                "PATH": f"{os.environ['PATH']}:{gradle_path}/bin",
                "JAVA_HOME": java_path,
            },
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[build_one] Build succeeded for {project_slug} with Gradle {gradle_version} and JDK {jdk_version}")
        save_build_info(project_slug, attempt)
        return NEWLY_BUILT
        
    except subprocess.CalledProcessError as e:
        print(f"[build_one] Build failed for {project_slug} with Gradle {gradle_version} and JDK {jdk_version}")
        print(f"Return code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return FAILED


def build_with_gradlew(project_slug, attempt):
    """Build project using gradlew script."""
    target_dir = Path(DATA_DIR) / "project-sources" / project_slug
    gradlew_path = target_dir / "gradlew"
    
    jdk_version = attempt['jdk']
    
    print(f"[build_one] Building {project_slug} with gradlew and JDK {jdk_version}...")
    
    if not gradlew_path.exists():
        print(f"[build_one] gradlew script not found in {target_dir}")
        return FAILED
    
    # Make gradlew executable
    try:
        subprocess.run(["chmod", "+x", str(gradlew_path)], check=True)
    except subprocess.CalledProcessError as e:
        print(f"[build_one] Failed to make gradlew executable: {e}")
        return FAILED
    
    # Validate Java path
    java_path = ALLVERSIONS["jdks"].get(jdk_version)
    if not java_path or not Path(java_path).exists():
        print(f"[build_one] JDK {jdk_version} not found.")
        return FAILED
    
    # Gradlew build command
    gradlew_cmd = ["./gradlew", "--no-daemon", "-S", "-Dorg.gradle.dependency.verification=off", "clean"]
    
    try:
        result = subprocess.run(
            gradlew_cmd,
            cwd=target_dir,
            env={"JAVA_HOME": java_path},
            capture_output=True,
            text=True,
            check=True
        )
        print(f"[build_one] Build succeeded for {project_slug} with gradlew and JDK {jdk_version}")
        save_build_info(project_slug, {"gradlew": 1, "jdk": jdk_version})
        return NEWLY_BUILT
        
    except subprocess.CalledProcessError as e:
        print(f"[build_one] Build failed for {project_slug} with gradlew and JDK {jdk_version}")
        print(f"Return code: {e.returncode}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
        return FAILED


def build_project_with_attempt(project_slug, attempt):
    """Build project using a specific attempt configuration."""
    # Check if already built
    if is_built(project_slug):
        print(f"[build_one] {project_slug} is already built...")
        return ALREADY_BUILT
    
    # Choose build method based on attempt configuration
    if "mvn" in attempt:
        return build_with_maven(project_slug, attempt)
    elif "gradle" in attempt:
        return build_with_gradle(project_slug, attempt)
    elif "gradlew" in attempt:
        return build_with_gradlew(project_slug, attempt)
    else:
        raise ValueError("Invalid attempt configuration: must specify mvn, gradle, or gradlew")


def try_build_with_attempt(project_slug, attempt, attempt_source=""):
    """Try to build a project with a specific attempt configuration."""
    if attempt_source:
        print(f"[build_one] Using {attempt_source} build configuration: {attempt}")
    
    result = build_project_with_attempt(project_slug, attempt)
    if result == NEWLY_BUILT:
        save_local_build_result(project_slug, True, attempt)
        return True
    elif result == ALREADY_BUILT:
        return True
    else:
        save_local_build_result(project_slug, False, attempt)
        return False


def validate_and_create_custom_attempt(jdk, mvn, gradle, gradlew):
    """Validate the provided versions and create a custom attempt configuration."""
    if not jdk:
        print("[build_one] Error: JDK version must be specified when using custom versions")
        sys.exit(1)
    
    # Validate JDK version
    if jdk not in ALLVERSIONS["jdks"]:
        available_jdks = list(ALLVERSIONS["jdks"].keys())
        print(f"[build_one] Error: JDK version '{jdk}' not found. Available JDK versions: {available_jdks}")
        sys.exit(1)
    
    custom_attempt = {"jdk": jdk}
    build_tool_count = 0
    
    # Validate and add Maven if specified
    if mvn:
        if mvn not in ALLVERSIONS["mvn"]:
            available_mvn = list(ALLVERSIONS["mvn"].keys())
            print(f"[build_one] Error: Maven version '{mvn}' not found. Available Maven versions: {available_mvn}")
            sys.exit(1)
        custom_attempt["mvn"] = mvn
        build_tool_count += 1
    
    # Validate and add Gradle if specified
    if gradle:
        if gradle not in ALLVERSIONS["gradle"]:
            available_gradle = list(ALLVERSIONS["gradle"].keys())
            print(f"[build_one] Error: Gradle version '{gradle}' not found. Available Gradle versions: {available_gradle}")
            sys.exit(1)
        custom_attempt["gradle"] = gradle
        build_tool_count += 1
    
    # Add gradlew if specified
    if gradlew:
        custom_attempt["gradlew"] = 1
        build_tool_count += 1
    
    # Ensure exactly one build tool is specified
    if build_tool_count == 0:
        print("[build_one] Error: At least one build tool must be specified (--mvn, --gradle, or --gradlew)")
        sys.exit(1)
    elif build_tool_count > 1:
        print("[build_one] Error: Only one build tool can be specified at a time (--mvn, --gradle, or --gradlew)")
        sys.exit(1)
    
    return custom_attempt


def build_inside_container(project_slug: str, attempt: dict) -> bool:
    image = parse_project_image(project_slug)
    ensure_image(image)
    container = create_container(image=image, working_dir="/workspace/repo")
    try:
        container.start()
        env = {}
        cmd: list[str]
        if "mvn" in attempt:
            cmd = ["bash", "-lc", "mvn -B -e -U -DskipTests clean package"]
        elif "gradle" in attempt:
            cmd = ["bash", "-lc", "gradle build --parallel"]
        elif "gradlew" in attempt:
            cmd = ["bash", "-lc", "chmod +x ./gradlew && ./gradlew --no-daemon -S -Dorg.gradle.dependency.verification=off clean"]
        else:
            return False
        code, _ = exec_in_container(container, cmd, workdir="/workspace/repo", environment=env, stream=True)
        return code == 0
    finally:
        try:
            container.remove(force=True)
        except Exception:
            pass


def build_project(project_slug, try_all=False, custom_attempt=None, use_container: bool = False):
    """Main function to build a project with various strategies."""
    # Handle custom attempt first
    if custom_attempt:
        if try_build_with_attempt(project_slug, custom_attempt, "custom"):
            return True
        print(f"[build_one] Custom build configuration failed for {project_slug}")
        return False

    # Try known configurations unless try_all is True
    if not try_all:
        # Try local build info first
        local_build_info = get_build_info_from_csv(project_slug, f"{DATA_DIR}/build-info/build_info_local.csv")
        if local_build_info and (try_build_with_attempt(project_slug, local_build_info, "local") if not use_container else build_inside_container(project_slug, local_build_info)):
            return True
        
        # Try global build info if local failed
        global_build_info = get_build_info_from_csv(project_slug, f"{DATA_DIR}/build_info.csv")
        if global_build_info and (try_build_with_attempt(project_slug, global_build_info, "global") if not use_container else build_inside_container(project_slug, global_build_info)):
            return True

    # Try all default attempts
    print("[build_one] " + 
          ("Skipping build info check and trying all version combinations..." if try_all else 
           "No successful build configuration found in CSV files, trying all version combinations..."))

    for attempt in ATTEMPTS:
        if (try_build_with_attempt(project_slug, attempt) if not use_container else build_inside_container(project_slug, attempt)):
            return True
    
    print(f"[build_one] All build attempts failed for {project_slug}")
    return False


def main():
    """Main function to handle argument parsing and project building."""
    parser = argparse.ArgumentParser(
        description="Build a single Java project with various build configurations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 build_one.py apache__camel_CVE-2018-8041_2.20.3
  python3 build_one.py spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE --jdk 11 --mvn 3.9.8
  python3 build_one.py apache__shiro_CVE-2023-34478_1.11.0 --try_all
        """
    )
    
    parser.add_argument(
        "project_slug", 
        type=str, 
        help="Project slug (e.g., apache__camel_CVE-2018-8041_2.20.3)"
    )
    parser.add_argument(
        "--try_all", 
        action="store_true", 
        help="Skip build info check and try all version combinations"
    )
    
    # Custom version arguments
    parser.add_argument(
        "--jdk", 
        type=str, 
        help="Specific JDK version to use (e.g., '8', '11', '17')"
    )
    parser.add_argument(
        "--mvn", 
        type=str, 
        help="Specific Maven version to use (e.g., '3.5.0', '3.9.8')"
    )
    parser.add_argument(
        "--gradle", 
        type=str, 
        help="Specific Gradle version to use (e.g., '6.8.2', '7.6.4', '8.9')"
    )
    parser.add_argument(
        "--gradlew", 
        action="store_true", 
        help="Use the project's gradlew script"
    )
    parser.add_argument(
        "--use-container",
        action="store_true",
        help="Build inside the project's container image",
    )
    
    args = parser.parse_args()
    
    # Check if custom versions are specified
    custom_attempt = None
    if args.jdk or args.mvn or args.gradle or args.gradlew:
        if args.try_all:
            print("[build_one] Error: Cannot use --try_all with custom version arguments")
            return 1
        custom_attempt = validate_and_create_custom_attempt(args.jdk, args.mvn, args.gradle, args.gradlew)
    
    success = build_project(args.project_slug, try_all=args.try_all, custom_attempt=custom_attempt, use_container=args.use_container)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
