import os

IRIS_ROOT_DIR = os.path.join(os.path.dirname(__file__), "..")


# CODEQL_DIR should be the path of the patched version of CodeQL provided as a download in the releases section for Iris.
CODEQL_DIR = f"{IRIS_ROOT_DIR}/codeql"

# CODEQL_DB_PATH is the path to the directory that contains CodeQL databases.
CODEQL_DB_PATH = f"{IRIS_ROOT_DIR}/data/codeql-dbs"

# PROJECT_SOURCE_CODE_DIR contains the Java projects. 
PROJECT_SOURCE_CODE_DIR = f"{IRIS_ROOT_DIR}/data/project-sources"

# PACKAGE_MODULES_PATH contains each project's internal modules. 
PACKAGE_MODULES_PATH = f"{IRIS_ROOT_DIR}/data/package-names"

# OUTPUT_DIR is where the results from running Iris are stored.
OUTPUT_DIR = f"{IRIS_ROOT_DIR}/output"

# ALL_METHOD_INFO_DIR  
ALL_METHOD_INFO_DIR = f"{IRIS_ROOT_DIR}/data/fix_info.csv"

# BUILD INFO DIR 
BUILD_INFO = f"{IRIS_ROOT_DIR}/data/build_info.csv"

# CVES_MAPPED_W_COMMITS_DIR is the path to project_info.csv, which contains the mapping of vulnerabilities to projects in cwe-bench-java. 
CVES_MAPPED_W_COMMITS_DIR = f"{IRIS_ROOT_DIR}/data/project_info.csv"

# Path to cwe-bench-java directory submodule.
DATA_DIR = f"{IRIS_ROOT_DIR}/data"

DEP_CONFIGS = f"{IRIS_ROOT_DIR}/dep_configs.json"

# this must be changed when the CodeQL query version is updated
# CODEQL_QUERY_VERSION is the version of the CodeQL queries used in Iris.
# This values should match qlpacks/codeql/java-queries/{CODEQL_QUERY_VERSION}
CODEQL_QUERY_VERSION = "1.8.1"
