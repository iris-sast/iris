import os
import sys
import subprocess as sp
import pandas as pd
import shutil
import json
import re
import argparse
import numpy as np
import copy
import math
import random

import requests
from tqdm import tqdm
from tqdm.contrib.concurrent import thread_map

THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
NEUROSYMSA_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../")
sys.path.append(NEUROSYMSA_ROOT_DIR)

from src.config import CODEQL_DIR, CODEQL_DB_PATH, OUTPUT_DIR, ALL_METHOD_INFO_DIR, PROJECT_SOURCE_CODE_DIR, CVES_MAPPED_W_COMMITS_DIR, CODEQL_QUERY_VERSION, IRIS_ROOT_DIR


from src.logger import Logger
from src.queries import QUERIES
from src.prompts import API_LABELLING_SYSTEM_PROMPT, API_LABELLING_USER_PROMPT
from src.prompts import FUNC_PARAM_LABELLING_SYSTEM_PROMPT, FUNC_PARAM_LABELLING_USER_PROMPT
from src.prompts import POSTHOC_FILTER_SYSTEM_PROMPT, POSTHOC_FILTER_USER_PROMPT, POSTHOC_FILTER_HINTS, SNIPPET_CONTEXT_SIZE
from src.codeql_queries import QL_SOURCE_PREDICATE, QL_STEP_PREDICATE, QL_SINK_PREDICATE
from src.codeql_queries import EXTENSION_YML_TEMPLATE, EXTENSION_SRC_SINK_YML_ENTRY, EXTENSION_SUMMARY_YML_ENTRY
from src.codeql_queries import QL_METHOD_CALL_SOURCE_BODY_ENTRY, QL_FUNC_PARAM_SOURCE_ENTRY, QL_FUNC_PARAM_NAME_ENTRY
from src.codeql_queries import QL_SUMMARY_BODY_ENTRY, QL_BODY_OR_SEPARATOR
from src.codeql_queries import QL_SINK_BODY_ENTRY, QL_SINK_ARG_NAME_ENTRY, QL_SINK_ARG_THIS_ENTRY

from src.modules.codeql_query_runner import CodeQLQueryRunner
from src.modules.evaluation_pipeline import EvaluationPipeline


class CodeQLSAPipeline:
    def __init__(
            self,
            project_name: str,
            query: str,
            evaluation_only: bool = False,
            overwrite: bool = False
    ):
        # Store basic information
        self.project_name = project_name
        self.query = query
        self.evaluation_only = evaluation_only
        self.overwrite = overwrite

        # Setup logger
        self.master_logger = Logger(f"{IRIS_ROOT_DIR}/log")

        # Check if the query is valid
        if self.query in QUERIES:
            if "cwe_id" not in QUERIES[self.query]:
                self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
                self.master_logger.error(f"==> Query `{self.query}` is not a query for detecting CWE; aborting"); exit(1)
        else:
            self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}, Trial: {self.run_id})...")
            self.master_logger.error(f"==> Unknown query `{self.query}`; aborting"); exit(1)
        self.cwe_id = QUERIES[self.query]["cwe_id"]
        self.experimental = QUERIES[self.query]["experimental"]
        self.cve_id = project_name.split("_")[3]

        # Load some basic information, such as commits and fixes related to the CVE
        self.all_cves_with_commit = pd.read_csv(CVES_MAPPED_W_COMMITS_DIR)
        self.project_cve_with_commit_info = self.all_cves_with_commit[self.all_cves_with_commit["cve"] == self.cve_id].iloc[0]
        self.cve_fixing_commits = self.project_cve_with_commit_info["commits"].split(";")
        self.fixed_methods = pd.read_csv(ALL_METHOD_INFO_DIR)
        self.project_fixed_methods = self.fixed_methods[self.fixed_methods["db_name"] == self.project_name]
        self.project_source_code_dir = f"{PROJECT_SOURCE_CODE_DIR}/{self.project_name}"

        # Basic path information
        self.project_output_path = f"{OUTPUT_DIR}/{self.project_name}/common"

        # Setup codeql database path
        self.project_codeql_db_path = f"{CODEQL_DB_PATH}/{self.project_name}"
        if not os.path.exists(f"{self.project_codeql_db_path}/db-java"):
            self.master_logger.info(f"Processing {self.project_name} (Query: {self.query}...")
            self.master_logger.error(f"==> Cannot find CodeQL database for {self.project_name}; aborting"); exit(1)

        # Setup query output path
        self.query_output_path = f"{self.project_output_path}/{self.query}"
        os.makedirs(self.query_output_path, exist_ok=True)
        self.query_output_result_sarif_path = f"{self.query_output_path}/results.sarif"
        self.query_output_result_csv_path = f"{self.query_output_path}/results.csv"
        self.final_output_json_path = f"{self.query_output_path}/results.json"

        # Function and Class locations
        self.func_locs_path = f"{self.project_output_path}/fetch_func_locs/results.csv"
        self.class_locs_path = f"{self.project_output_path}/fetch_class_locs/results.csv"

    def run_codeql_query(self):
        self.master_logger.info("==> Stage 1: Running CodeQL queries...")

        exp = "experimental/" if self.experimental else ""

        cmd = [
            "codeql",
            "database",
            "analyze",
            self.project_codeql_db_path,
            f"--output={self.query_output_result_sarif_path}",
            f"{CODEQL_DIR}/qlpacks/codeql/java-queries/{CODEQL_QUERY_VERSION}/{exp}Security/CWE/CWE-{self.cwe_id}/"
        ]

        if self.overwrite:
            cmd += ["--rerun"]

        sp.run(cmd + ["--format=sarif-latest"])

        sp.run(cmd + ["--format=csv"])

    def run_simple_codeql_query(self, query, target_csv_path=None, suffix=None, dyn_queries={}):
        runner = CodeQLQueryRunner(self.project_output_path, self.project_codeql_db_path, self.master_logger)
        runner.run(query, target_csv_path, suffix, dyn_queries)

    def extract_class_locations(self):
        if not os.path.exists(self.class_locs_path):
            self.master_logger.info(f"  ==> Class locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_class_locs")

    def extract_func_locations(self):
        if not os.path.exists(self.func_locs_path):
            self.master_logger.info(f"  ==> Function locations not found; running CodeQL query to extract...")
            self.run_simple_codeql_query("fetch_func_locs")

    def build_evaluation_pipeline(self):
        return EvaluationPipeline(
            self.project_fixed_methods,
            self.class_locs_path,
            self.func_locs_path,
            self.project_source_code_dir,
            query_output_result_sarif_path=self.query_output_result_sarif_path,
            final_output_json_path=self.final_output_json_path,
            overwrite=self.overwrite,
            project_logger=self.master_logger,
        )

    def evaluate_result(self):
        self.master_logger.info("==> Stage 2: Evaluating results...")

        # 1. Extract class and function locations
        self.master_logger.info("  ==> Extracting function and class locations...")
        self.extract_class_locations()
        self.extract_func_locations()

        # 2. Build
        self.master_logger.info("  ==> Evaluating results...")
        eval_pipeline = self.build_evaluation_pipeline()
        eval_pipeline.run_vanilla_only()

    def run(self):
        if self.evaluation_only:
            self.evaluate_result()
        else:
            self.run_codeql_query()
            self.evaluate_result()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=str)
    parser.add_argument("--query", type=str, default="cwe-022wCodeQL", required=True)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--evaluation-only", action="store_true")
    args = parser.parse_args()

    pipeline = CodeQLSAPipeline(
        args.project,
        args.query,
        evaluation_only=args.evaluation_only,
        overwrite=args.overwrite,
    )
    pipeline.run()
