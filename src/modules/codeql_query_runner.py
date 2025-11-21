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

from src.config import CODEQL_DIR
from src.queries import QUERIES

CODEQL = f"{CODEQL_DIR}/codeql"

ENTRY_SCRIPT_DIR = os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "/../")

class CodeQLQueryRunner:
    def __init__(self, project_output_path, project_codeql_db_path, project_logger):
        self.project_output_path = project_output_path
        self.project_codeql_db_path = project_codeql_db_path
        self.project_logger = project_logger

    def run(self, query, target_csv_path=None, suffix=None, dyn_queries={}):
        """
        :param query, is a string that should be a key in the QUERIES dictionary
        :param target_csv_path, is a path where the result csv should be stored to
        :param suffix, ???
        :param dyn_queries, is a dictionary {<name>: <content>} of dyanmically generated queries.
                            The name needs to be ending with a `.ql` or `.qll` extension.
        """
        # 0. Sanity check
        if query not in QUERIES:
            self.project_logger.error(f"  ==> Unknown query `{query}`; aborting"); exit(1)

        # 1. Create the directory in CodeQL's queries path
        suffix_dir = "" if suffix is None else f"/{suffix}"
        codeql_query_dir = f"{self.project_output_path}/myqueries/{query}{suffix_dir}"
        os.makedirs(codeql_query_dir, exist_ok=True)

        # 2. Copy the basic queries and supporting queries to the codeql directory
        for q in QUERIES[query]["queries"]:
            shutil.copy(f"{ENTRY_SCRIPT_DIR}/{q}", f"{codeql_query_dir}/")

        # 3. Write the dynamic queries
        for dyn_query_name, content in dyn_queries.items():
            with open(f"{codeql_query_dir}/{dyn_query_name}", "w") as f:
                f.write(content)
                
        pack_root = f"{self.project_output_path}/myqueries"
        try:
            sp.run([CODEQL, "pack", "install"], cwd=pack_root, check=False)
        except Exception as e:
            self.project_logger.error(f"  ==> Failed during 'codeql pack install': {e}; aborting"); exit(1)
        lock_file_path = f"{pack_root}/codeql-pack.lock.yml"
        if not os.path.exists(lock_file_path):
            self.project_logger.error("  ==> Failed to install CodeQL packs (missing codeql-pack.lock.yml); aborting"); exit(1)
            
        # 4. Setup the paths
        main_query = QUERIES[query]["queries"][0]
        main_query_name = main_query.split("/")[-1]
        codeql_query_path = f"{codeql_query_dir}/{main_query_name}"

        query_result_path = f"{self.project_output_path}/{query}{suffix_dir}"
        query_result_bqrs_path = f"{self.project_output_path}/{query}{suffix_dir}/results.bqrs"
        query_result_csv_path = f"{self.project_output_path}/{query}{suffix_dir}/results.csv"
        os.makedirs(query_result_path, exist_ok=True)

        # 5. Run the query and generate result bqrs
        sp.run([CODEQL, "query", "run", f"--database={self.project_codeql_db_path}", f"--output={query_result_bqrs_path}", "--", codeql_query_path])
        if not os.path.exists(query_result_bqrs_path):
            self.project_logger.error(f"  ==> Failed to run query `{query}`; aborting"); exit(1)

        # 6. Decode the query
        sp.run([CODEQL, "bqrs", "decode", query_result_bqrs_path, "--format=csv", f"--output={query_result_csv_path}"])
        if not os.path.exists(query_result_csv_path):
            self.project_logger.error(f"  ==> Failed to decode result bqrs from `{query}`; aborting"); exit(1)

        # 7. Copy the query out
        if target_csv_path is not None:
            shutil.copy(query_result_csv_path, target_csv_path)
