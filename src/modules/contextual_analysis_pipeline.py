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

from tqdm import tqdm
from tqdm.contrib.concurrent import thread_map

from src.prompts import POSTHOC_FILTER_SYSTEM_PROMPT, POSTHOC_FILTER_USER_PROMPT, POSTHOC_FILTER_USER_PROMPT_W_CONTEXT, POSTHOC_FILTER_HINTS, SNIPPET_CONTEXT_SIZE
from src.queries import QUERIES

from src.models.gpt import GPTModel
from src.models.llm import LLM

class ContextualAnalysisPipeline:
    def __init__(
            self,
            query,
            cwe_id,
            llm,
            seed,
            class_locs_path,
            func_locs_path,
            project_fixed_methods,
            query_output_result_sarif_path,
            posthoc_filtering_output_log_path,
            posthoc_filtering_output_result_json_path,
            posthoc_filtering_output_result_sarif_path,
            posthoc_filtering_output_stats_json_path,
            project_source_code_dir,
            project_logger,
            overwrite,
            overwrite_posthoc_filter,
            test_run,
            posthoc_filtering_skip_fp: bool = False,
            rerun_skipped_fp: bool = False,
            skip_check_fixed_method: bool = False,
            batch_size: int = 3,
    ):
        self.query = query
        self.cwe_id = cwe_id
        self.llm = llm
        self.model = None
        self.seed = seed
        self.class_locs_path = class_locs_path
        self.func_locs_path = func_locs_path
        self.project_fixed_methods = project_fixed_methods
        self.query_output_result_sarif_path = query_output_result_sarif_path
        self.posthoc_filtering_output_log_path = posthoc_filtering_output_log_path
        self.posthoc_filtering_output_result_json_path = posthoc_filtering_output_result_json_path
        self.posthoc_filtering_output_result_sarif_path = posthoc_filtering_output_result_sarif_path
        self.posthoc_filtering_output_stats_json_path = posthoc_filtering_output_stats_json_path
        self.project_source_code_dir = project_source_code_dir
        self.project_logger = project_logger
        self.overwrite = overwrite
        self.overwrite_posthoc_filter = overwrite_posthoc_filter
        self.test_run = test_run
        self.posthoc_filtering_skip_fp = posthoc_filtering_skip_fp
        self.rerun_skipped_fp = rerun_skipped_fp
        self.batch_size = batch_size
        self.skip_check_fixed_method = skip_check_fixed_method
        self.alarm_results = {}

    def get_model(self):
        if self.model is None:
            self.model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed, "max_new_tokens": 2048})
        return self.model

    def extract_enclosing_decl_locs_map(self, decl_locs):
        """
        Extract enclosing declaration locations mapping from a pandas DataFrame

        :param decl_locs, a pandas DataFrame containing function or class locations
        :returns a mapping from file name to list of declarations defined in that file.
                 each declaration is a tuple (<decl_name>, <start_line>, <end_line>)
        """
        enclosing_decl_locs = {}
        for (i, row) in decl_locs.iterrows():
            if row["file"] not in enclosing_decl_locs:
                enclosing_decl_locs[row["file"]] = []
            enclosing_decl_locs[row["file"]].append((row["name"], row["start_line"], row["end_line"]))
        return enclosing_decl_locs

    def iter_code_flows(self, sarif_json):
        """
        Iterate through the code flows within a SARIF json obtained from running path queries with CodeQL
        """
        for (i, result) in enumerate(sarif_json["runs"][0]["results"]):
            if "codeFlows" not in result: continue
            code_flows = result["codeFlows"]
            for (j, code_flow) in enumerate(code_flows):
                yield (i, j, code_flow)

    def iter_code_flows_for_query(self, sarif_json):
        for (i, j, code_flow) in self.iter_code_flows(sarif_json):
            thread_flow = code_flow["threadFlows"][0]
            locations = thread_flow["locations"]
            path_locations = []
            for loc in locations:
                try:
                    file_url = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
                    region = loc["location"]["physicalLocation"]["region"]
                    start_line = region["startLine"]
                    start_column = region["startColumn"] if "startColumn" in region else 0
                    end_line = start_line if "endLine" not in region else region["endLine"]
                    end_column = region["endColumn"]
                    message = loc["location"]["message"]["text"]
                    path_locations.append({
                        "file_url": file_url,
                        "start_line": start_line,
                        "start_column": start_column,
                        "end_line": end_line,
                        "end_column": end_column,
                        "message": message
                    })
                except Exception as e:
                    self.project_logger.error(f"Error extracting location: {e}")
                    continue
            yield (i, j, path_locations)

    def find_enclosing_declaration(self, start_line, end_line, decl_locs):
        closest_start_end = None
        for decl_loc in decl_locs:
            if decl_loc[1] <= start_line and end_line <= decl_loc[2]:
                if closest_start_end is None:
                    closest_start_end = decl_loc
                else:
                    if decl_loc[1] > closest_start_end[1]:
                        closest_start_end = decl_loc
        return closest_start_end

    def path_location_to_enclose_func_and_msg(self, loc, enclosing_func_locs):
        file_url = loc["file_url"]
        if file_url in enclosing_func_locs:
            enclosing_func = self.find_enclosing_declaration(loc["start_line"], loc["end_line"], enclosing_func_locs[file_url])
            if enclosing_func:
                func_name = enclosing_func[0]
                message = loc["message"]
                return f"{file_url}:{func_name}:{message}"
        return f"{file_url}#{loc['start_line']}"

    def encode_path_group_id(self, path, enclosing_func_locs):
        source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
        sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
        return (source, sink)

    def get_snippet_from_loc(
            self,
            loc,
            kind,
            enclosing_class_locs,
            enclosing_func_locs,
    ):
        """
        :param loc, { "file_url": <FILE>, "start_line": <LINE>, "end_line": <LINE> }
        :param kind, str of "SOURCE" or "SINK"
        :param enclosing_class_locs, { <FILE>: [ (<CLASS_NAME>, <START_LINE>, <END_LINE>) ] }
        :param enclosing_func_locs, { <FILE>: [ (<FUNC_NAME>, <START_LINE>, <END_LINE>) ] }
        """
        # Get the file lines
        file_dir = f"{self.project_source_code_dir}/{loc['file_url']}"
        if not os.path.exists(file_dir):
            print("Not found ", file_dir)
            return None, (None, None, None)
        file_lines = list(open(file_dir, 'r').readlines())

        # Get the start and end lines
        start_line, end_line = loc['start_line'], loc['end_line']

        # Get the enclosing class
        class_start_end = self.find_enclosing_declaration(start_line, end_line, enclosing_class_locs[loc["file_url"]])
        if class_start_end:
            class_decl_str = file_lines[class_start_end[1] - 1].strip()
            if class_decl_str == "":
                class_decl_str = None
            elif class_decl_str[-1] != "{":
                class_decl_str += " {"
        else:
            class_decl_str = None

        # Get the enclosing function
        if loc["file_url"] in enclosing_func_locs:
            func_start_end = self.find_enclosing_declaration(start_line, end_line, enclosing_func_locs[loc["file_url"]])
            if func_start_end:
                func_decl_str = file_lines[func_start_end[1] - 1].strip()
                if len(func_decl_str) == 0:
                    func_decl_str = f"{func_start_end[0]} () {{"
                elif func_decl_str[-1] != "{":
                    func_decl_str += " {"
            else:
                func_decl_str = None
        else:
            func_start_end = None
            func_decl_str = None

        # Compute the boundary
        boundary = (0, len(file_lines))
        if class_start_end: boundary = class_start_end[1:]
        if func_start_end: boundary = func_start_end[1:]

        # Snippet start and end line
        snippet_start = max(start_line - 2 - SNIPPET_CONTEXT_SIZE, boundary[0])
        start_ellipses = "...\n" if snippet_start > boundary[0] else ""
        snippet_end = min(end_line + SNIPPET_CONTEXT_SIZE, boundary[1] - 1)
        end_ellipses = "    ..." if snippet_end < boundary[1] - 2 else ""

        # Snippet
        snippet = ""
        base_snippet = ""
        for line_num in range(snippet_start, snippet_end):
            line = file_lines[line_num]
            if line_num == loc['start_line'] - 1:
                # Need to remove the last new line and add a new comment
                snippet += line[:-1] + f" // <---- THIS IS THE {kind.upper()}\n"
                base_snippet += line[:-1]
            elif line.strip() != "":
                snippet += line
                base_snippet += line

        # Combine them into a full snippet with class and func decl
        if func_decl_str is None:
            snippet_with_decl = f"""{class_decl_str}\n    {start_ellipses}{snippet}{end_ellipses}\n}}"""
        else:
            snippet_with_decl = f"""{class_decl_str}\n  {func_decl_str}\n    {start_ellipses}{snippet}{end_ellipses}\n  }}\n}}"""

        return snippet_with_decl, (base_snippet, func_decl_str, class_decl_str)

    def intermediate_step_prompt(self, i, loc, enclosing_func_locs):
        file_name = loc["file_url"].split("/")[-1]

        file_dir = f"{self.project_source_code_dir}/{loc['file_url']}"
        if not os.path.exists(file_dir): return None
        file_lines = list(open(file_dir, 'r').readlines())
        line = file_lines[loc["start_line"] - 1].strip()

        func_name = ""
        if loc["file_url"] in enclosing_func_locs:
            enclosing = self.find_enclosing_declaration(loc["start_line"], loc["start_line"], enclosing_func_locs[loc["file_url"]])
            if enclosing is not None:
                func_name = f":{enclosing[0]}"

        return f"- Step {i + 1} [{file_name}{func_name}]: {line}"

    def intermediate_steps_prompt(self, path_locs, enclosing_func_locs):
        step_size = max(1, math.floor(len(path_locs) / 10))
        trimmed_path_locs = path_locs[1:-1:step_size]
        result_str = ""
        for (i, loc) in enumerate(trimmed_path_locs):
            if i > 0:
                result_str += "\n"
            prompt = self.intermediate_step_prompt(i, loc, enclosing_func_locs)
            if prompt is not None:
                result_str += prompt
        return result_str

    def path_locs_to_user_prompt(self, path_locs, enclosing_class_locs, enclosing_func_locs):
        start_loc, end_loc = path_locs[0], path_locs[-1]
        start_snippet, start_raw_snippets = self.get_snippet_from_loc(start_loc, "source", enclosing_class_locs, enclosing_func_locs)
        intermediate_steps = self.intermediate_steps_prompt(path_locs, enclosing_func_locs)
        end_snippet, end_raw_snippets = self.get_snippet_from_loc(end_loc, "sink", enclosing_class_locs, enclosing_func_locs)
        start_code_snippet, func_decl_str, class_decl_str = start_raw_snippets
        prompt = POSTHOC_FILTER_USER_PROMPT.format(
            cwe_description=QUERIES[self.query]['desc'],
            cwe_id=f"CWE-{QUERIES[self.query]['cwe_id']}",
            hint=POSTHOC_FILTER_HINTS[self.cwe_id],
            source_msg=start_loc["message"],
            source=start_snippet,
            intermediate_steps=intermediate_steps,
            sink_msg=end_loc["message"],
            sink=end_snippet)
        return prompt

    def parse_boolean(self, value):
        if type(value) == str:
            if value == "true" or value == "True": return True
            elif value == "false" or value == "False": return False
        elif type(value) == int:
            return value != 0
        elif type(value) == bool:
            return value
        else:
            return None

    def parse_posthoc_filter_json_result(self, json_str):
        try:
            # Remove markdown code block markers if present
            json_str = re.sub(r'```json\s*', '', json_str)
            json_str = re.sub(r'```\s*$', '', json_str)

            # Handle escaped single quotes which are invalid in JSON
            json_str = json_str.replace("\\'", "'")

            # Original cleanup
            json_str = json_str.replace("\\n", "").replace("\\\n", "")
            json_str = re.sub("//.*", "", json_str)
            json_str = re.sub("\"\"", "\"", json_str)

            # Extract JSON object
            json_match = re.findall(r"\{[\s\S]*\}", json_str)
            if not json_match:
                self.project_logger.error(f"    ==> No JSON object found in response")
                return {}

            result = json.loads(json_match[0])
            if type(result) == dict:
                if "is_vulnerable" in result: result["is_vulnerable"] = self.parse_boolean(result["is_vulnerable"])
                if "source_is_false_positive" in result: result["source_is_false_positive"] = self.parse_boolean(result["source_is_false_positive"])
                if "sink_is_false_positive" in result: result["sink_is_false_positive"] = self.parse_boolean(result["sink_is_false_positive"])
                return result
            else:
                return {}
        except Exception as e:
            self.project_logger.error(f"    ==> Error parsing JSON: {e}")
            # Log the problematic JSON string for debugging
            self.project_logger.error(f"    ==> Problematic JSON string: {repr(json_str[:500])}")
            return {}

    def query_gpt_on_posthoc_filter_prompt(self, result_id, code_flow_id, path_user_prompt):
        #model = LLM.get_llm(model_name=self.llm, logger=self.project_logger, kwargs={"seed": self.seed})
        try:
            # Dump the user prompt
            with open(f"{self.posthoc_filtering_output_log_path}/raw_user_prompt_{result_id}_{code_flow_id}.txt", "w") as f:
                f.write(path_user_prompt)

            # Generate full prompt and send to LLM
            if isinstance(self.get_model(), GPTModel):
                result_str = self.get_model().predict([
                    {"role": "system", "content": POSTHOC_FILTER_SYSTEM_PROMPT},
                    {"role": "user", "content": path_user_prompt},
                ], expect_json=True)
            else:
                result_str = self.get_model().predict([
                    {"role": "system", "content": POSTHOC_FILTER_SYSTEM_PROMPT},
                    {"role": "user", "content": path_user_prompt},
                ])

            # Dump the raw LLM outputs
            with open(f"{self.posthoc_filtering_output_log_path}/raw_llm_response_{result_id}_{code_flow_id}.txt", "w") as f:
                f.write(result_str)

            result_json = self.parse_posthoc_filter_json_result(result_str)
            return result_json
        except Exception as e:
            self.project_logger.error(f"Error when querying LLM: {e}")
            return {}

    def use_cache_on_code_flow(
            self,
            result_id,
            code_flow_id,
            path,
            enclosing_func_locs,
            grouped_path_cache,
            false_positive_source_cache,
            false_positive_sink_cache,
    ):
        """
        There are a few ways we apply cache

        1. We group paths by their source and sinks. If a path in a group is queried with results, subsequent calls would not be made.
        All similar paths would have exactly the same result as the existing one

        2. For each query, we note down whether the source or the sink is false positive. If a source/sink is marked false positive,
        and that a subsequent path has the same source/sink, we would mark the path as NOT VULNERABLE (false).
        """
        source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
        sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
        group_id = (source, sink)

        # The first caching strategy
        if group_id in grouped_path_cache:
            using_cache = True
            result = grouped_path_cache[group_id]

        elif result_id in self.alarm_results and self.alarm_results[result_id] is not None:
            using_cache = True
            result = self.alarm_results[result_id]

        # The second caching strategy where Source is cached to be false positive
        elif source in false_positive_source_cache and false_positive_source_cache[source]:
            using_cache = True
            sink_is_false_positive = false_positive_sink_cache[sink] if sink in false_positive_sink_cache else None
            result = {
                "is_vulnerable": False,
                "source_is_false_positive": True,
                "sink_is_false_positive": sink_is_false_positive,
                "explanation": "[Caching] Source is marked false positive in a previous call to GPT"
            }
            grouped_path_cache[group_id] = result
            self.alarm_results[result_id] = result

        # The second caching strategy where Sink is cached to be false positive
        elif sink in false_positive_sink_cache and false_positive_sink_cache[sink]:
            using_cache = True
            source_is_false_positive = false_positive_source_cache[source] if source in false_positive_source_cache else None
            result = {
                "is_vulnerable": False,
                "source_is_false_positive": source_is_false_positive,
                "sink_is_false_positive": True,
                "explanation": "[Caching] Sink is marked false positive in a previous call to GPT"
            }
            grouped_path_cache[group_id] = result
            self.alarm_results[result_id] = result

        # No caching available, make the query
        else:
            result = None

        return result

    def query_gpt_on_code_flow_or_use_cache(
            self,
            result_id,
            code_flow_id,
            path,
            enclosing_class_locs,
            enclosing_func_locs,
            grouped_path_cache,
            false_positive_source_cache,
            false_positive_sink_cache,
    ):
        """
        There are a few ways we apply cache

        1. We group paths by their source and sinks. If a path in a group is queried with results, subsequent calls would not be made.
        All similar paths would have exactly the same result as the existing one

        2. For each query, we note down whether the source or the sink is false positive. If a source/sink is marked false positive,
        and that a subsequent path has the same source/sink, we would mark the path as NOT VULNERABLE (false).
        """
        source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
        sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
        group_id = (source, sink)
        path_user_prompt = self.path_locs_to_user_prompt(path, enclosing_class_locs, enclosing_func_locs)

        if self.test_run:
            print(path_user_prompt)

        # The first caching strategy
        if group_id in grouped_path_cache:
            using_cache = True
            result = grouped_path_cache[group_id]

        # The second caching strategy where Source is cached to be false positive
        elif source in false_positive_source_cache and false_positive_source_cache[source]:
            using_cache = True
            sink_is_false_positive = false_positive_sink_cache[sink] if sink in false_positive_sink_cache else None
            result = {
                "is_vulnerable": False,
                "source_is_false_positive": True,
                "sink_is_false_positive": sink_is_false_positive,
                "explanation": "[Caching] Source is marked false positive in a previous call to GPT"
            }
            grouped_path_cache[group_id] = result
            self.alarm_results[result_id] = result

        # The second caching strategy where Sink is cached to be false positive
        elif sink in false_positive_sink_cache and false_positive_sink_cache[sink]:
            using_cache = True
            source_is_false_positive = false_positive_source_cache[source] if source in false_positive_source_cache else None
            result = {
                "is_vulnerable": False,
                "source_is_false_positive": source_is_false_positive,
                "sink_is_false_positive": True,
                "explanation": "[Caching] Sink is marked false positive in a previous call to GPT"
            }
            grouped_path_cache[group_id] = result
            self.alarm_results[result_id] = result

        # No caching available, make the query
        else:
            using_cache = False
            if self.test_run:
                result = {}
            else:
                result = self.query_gpt_on_posthoc_filter_prompt(result_id, code_flow_id, path_user_prompt)

            # Cache group id
            grouped_path_cache[group_id] = result
            self.alarm_results[result_id] = result

            # Cache false positiveness of source or sink
            if "source_is_false_positive" in result and result["source_is_false_positive"]:
                false_positive_source_cache[source] = True
            if "sink_is_false_positive" in result and result["sink_is_false_positive"]:
                false_positive_sink_cache[sink] = True

        # Return
        return {
            "path": path,
            "using_cache": using_cache,
            "prompt": path_user_prompt,
            "result": result,
        }

    def build_prompt_for_code_flow(self, path, enclosing_class_locs, enclosing_func_locs):
        path_user_prompt = self.path_locs_to_user_prompt(path, enclosing_class_locs, enclosing_func_locs)
        return [
            {"role": "system", "content": POSTHOC_FILTER_SYSTEM_PROMPT},
            {"role": "user", "content": path_user_prompt},
        ]

    def batched_query_gpt_on_code_flow(
            self,
            entries,
            enclosing_class_locs,
            enclosing_func_locs,
            grouped_path_cache,
            false_positive_source_cache,
            false_positive_sink_cache,
    ):
        prompts = [self.build_prompt_for_code_flow(path, enclosing_class_locs, enclosing_func_locs) for (_, _, path) in entries]

        # Dump
        for ((result_id, code_flow_id, _), prompt) in zip(entries, prompts):
            # Dump the user prompt
            with open(f"{self.posthoc_filtering_output_log_path}/raw_user_prompt_{result_id}_{code_flow_id}.txt", "w") as f:
                f.write(prompt[1]["content"])

        # Predict
        try:
            results = self.get_model().predict(prompts, batch_size=self.batch_size, no_progress_bar=True)
        except:
            self.project_logger.error("Error during querying; skipping")
            results = ["" for p in prompts]

        # Dump
        results_json = []
        for ((result_id, code_flow_id, path), prompt, result_str) in zip(entries, prompts, results):
            with open(f"{self.posthoc_filtering_output_log_path}/raw_llm_response_{result_id}_{code_flow_id}.txt", "w") as f:
                f.write(result_str)

            try:
                result_json = self.parse_posthoc_filter_json_result(result_str)
            except:
                result_json = {}

            source = self.path_location_to_enclose_func_and_msg(path[0], enclosing_func_locs)
            sink = self.path_location_to_enclose_func_and_msg(path[-1], enclosing_func_locs)
            group_id = (source, sink)

            # Cache group id
            grouped_path_cache[group_id] = result_json

            # Cache false positiveness of source or sink
            if "source_is_false_positive" in result_json and result_json["source_is_false_positive"]:
                false_positive_source_cache[source] = True
            if "sink_is_false_positive" in result_json and result_json["sink_is_false_positive"]:
                false_positive_sink_cache[sink] = True

            results_json.append((
                result_id,
                code_flow_id,
                {
                    "path": path,
                    "using_cache": False,
                    "prompt": prompt[1]["content"],
                    "result": result_json,
                }
            ))

        return results_json

    def retain_sarif_json_with_code_flow_ids(self, original_sarif_json, predicted_is_vulnerable_path_ids):
        new_sarif_json = copy.deepcopy(original_sarif_json)
        new_results = []
        for (result_id, old_result) in enumerate(original_sarif_json["runs"][0]["results"]):
            if "codeFlows" not in old_result:
                new_results.append(old_result)
            else:
                new_result = copy.deepcopy(old_result)
                new_code_flows = []
                for (code_flow_id, code_flow) in enumerate(old_result["codeFlows"]):
                    if (result_id, code_flow_id) in predicted_is_vulnerable_path_ids:
                        new_code_flows.append(code_flow)
                new_result["codeFlows"] = new_code_flows
                new_results.append(new_result)
        new_sarif_json["runs"][0]["results"] = new_results
        return new_sarif_json

    def ignore_code_flow(self, code_flow):
        first_location = code_flow[0]
        last_location = code_flow[-1]
        def has_to_string(loc):
            if "toString" in loc['message']: return True
            if "println" in loc['message']: return True
            if "... + ..." in loc['message']: return True
            if "next(" in loc['message']: return True
            if "getOptionValue(" in loc['message']: return True
            if "get(" in loc['message']: return True
            if "getProperty(" in loc['message']: return True
            return False
        ignore = False
        ignore = ignore or has_to_string(first_location)
        ignore = ignore or has_to_string(last_location)
        return ignore

    def extract_fixed_methods(self):
        fixed_methods = set()
        if self.skip_check_fixed_method:
            return fixed_methods
        for (_, row) in self.project_fixed_methods.iterrows():
            file_name, class_name, method_name = row["file"], row["class"], row["method"]
            if "src/test" in file_name: continue
            fixed_methods.add(f"{file_name}:{class_name}:{method_name}")
        return fixed_methods

    def extract_code_flow_passing_methods(self, project_classes, project_methods, code_flow):
        for loc in code_flow:
            file_url = loc["file_url"]
            start_line = loc["start_line"]

            # Get the closest enclosing class
            relevant_classes = project_classes[
                (project_classes["file"] == file_url) &
                (project_classes["start_line"] <= start_line) &
                (project_classes["end_line"] >= start_line)
            ].sort_values(by="start_line", ascending=False)
            if len(relevant_classes) == 0: continue
            relevant_class = relevant_classes.iloc[0]["name"]

            # Get the closest enclosing method
            relevant_methods = project_methods[
                (project_methods["file"] == file_url) &
                (project_methods["start_line"] <= start_line) &
                (project_methods["end_line"] >= start_line)
            ].sort_values(by="start_line", ascending=False)
            if len(relevant_methods) == 0: continue
            relevant_method = relevant_methods.iloc[0]["name"]

            # Yield
            yield f"{file_url}:{relevant_class}:{relevant_method}"

    def code_flow_passes_fix_method(self, code_flow, fixed_methods, project_classes, project_methods):
        # 4.1. Get recall@method
        passing_methods = set(self.extract_code_flow_passing_methods(project_classes, project_methods, code_flow))
        return len(fixed_methods.intersection(passing_methods)) > 0

    def run(self):
        # 0. Checking if this is already computed
        if os.path.exists(self.posthoc_filtering_output_result_sarif_path) and not self.overwrite and not self.overwrite_posthoc_filter:
            if self.rerun_skipped_fp:
                ran_sarif = json.load(open(self.posthoc_filtering_output_result_sarif_path))
                ran_codeflows = list(self.iter_code_flows_for_query(ran_sarif))
                if len(ran_codeflows) == 0:
                    # still need to run
                    pass
                else:
                    self.project_logger.info("  ==> Found existing posthoc filter results; skipping...")
                    return
            else:
                self.project_logger.info("  ==> Found existing posthoc filter results; skipping...")
                return
        if not os.path.exists(self.query_output_result_sarif_path) and self.test_run:
            self.project_logger.info("  ==> No result SARIF during test run; skipping...")
            return

        # 1. Extract class and function locations
        self.project_logger.info("  ==> Extracting function and class locations...")
        project_classes_csv = pd.read_csv(self.class_locs_path)
        project_classes = self.extract_enclosing_decl_locs_map(project_classes_csv)
        project_methods_csv = pd.read_csv(self.func_locs_path)
        project_methods = self.extract_enclosing_decl_locs_map(project_methods_csv)
        fixed_methods = self.extract_fixed_methods()

        # 2. Load the base SARIF
        self.project_logger.info("  ==> Loading result SARIF...")
        original_sarif = json.load(open(self.query_output_result_sarif_path))

        # 3. Setup caches so that we do not query LLM too many times, also setup stat variables
        grouped_path_cache, false_positive_source_cache, false_positive_sink_cache = {}, {}, {}
        num_processed, num_alerts, num_calls, num_cached, num_ignored, num_failure = 0, 0, 0, 0, 0, 0
        code_flow_results, predicted_is_vulnerable_path_ids = [], []

        # 4. Iterate through each code flow and query LLM for posthoc filtering
        all_code_flows = list(self.iter_code_flows_for_query(original_sarif))
        all_code_flows_iterator = tqdm(all_code_flows)
        to_query_batch = []
        for (i, (result_id, code_flow_id, code_flow)) in enumerate(all_code_flows_iterator):
            all_code_flows_iterator.set_description(f"#Processed: {num_processed}, #Alerts: {num_alerts}, #Calls: {num_calls}, #Cached: {num_cached}, #Fail: {num_failure}, #Ignored: {num_ignored}")
            use_cache_result = self.use_cache_on_code_flow(result_id, code_flow_id, code_flow, project_methods, grouped_path_cache, false_positive_source_cache, false_positive_sink_cache)
            if use_cache_result == None:
                if self.posthoc_filtering_skip_fp:
                    if not self.code_flow_passes_fix_method(code_flow, fixed_methods, project_classes_csv, project_methods_csv):
                        continue

                if self.ignore_code_flow(code_flow):
                    entry = {
                        "path": code_flow,
                        "prompt": "",
                        "using_cache": False,
                        "ignored_by_filter": True,
                        "result": False,
                    }

                    # 4.2. Store the result
                    code_flow_results.append({
                        "result_id": result_id,
                        "code_flow_id": code_flow_id,
                        "entry": entry,
                    })

                    # 4.3. Update the statistics
                    num_processed += 1
                    num_ignored += 1
                else:

                    if len(to_query_batch) < self.batch_size:
                        to_query_batch.append((result_id, code_flow_id, code_flow))

                    if len(to_query_batch) == self.batch_size or (len(to_query_batch) != 0 and i == len(all_code_flows) - 1):
                        entries = self.batched_query_gpt_on_code_flow(
                            to_query_batch, project_classes, project_methods,
                            grouped_path_cache, false_positive_source_cache, false_positive_sink_cache)

                        for (result_id, code_flow_id, entry) in entries:
                            code_flow_results.append({
                                "result_id": result_id,
                                "code_flow_id": code_flow_id,
                                "entry": entry,
                            })

                            # 4.3. Update the statistics
                            num_processed += 1
                            if "using_cache" in entry and entry["using_cache"]:
                                num_cached += 1
                            else:
                                num_calls += 1
                            if "is_vulnerable" in entry["result"]:
                                if entry["result"]["is_vulnerable"]:
                                    num_alerts += 1
                                    predicted_is_vulnerable_path_ids.append((result_id, code_flow_id))
                            else:
                                num_failure += 1

                        to_query_batch = []

            else:
                entry = {
                    "path": code_flow,
                    "prompt": "",
                    "using_cache": True,
                    "result": use_cache_result
                }

                # 4.2. Store the result
                code_flow_results.append({
                    "result_id": result_id,
                    "code_flow_id": code_flow_id,
                    "entry": entry,
                })

                # 4.3. Update the statistics
                num_processed += 1
                if entry["using_cache"]:
                    num_cached += 1
                else:
                    num_calls += 1
                if "is_vulnerable" in entry["result"]:
                    if entry["result"]["is_vulnerable"]:
                        num_alerts += 1
                        predicted_is_vulnerable_path_ids.append((result_id, code_flow_id))
                else:
                    num_failure += 1

        # 5. Dump the code flow query results
        if not self.test_run:
            json.dump(code_flow_results, open(self.posthoc_filtering_output_result_json_path, "w"))

        # 6. Create a new SARIF and dump it
        modified_sarif = self.retain_sarif_json_with_code_flow_ids(original_sarif, predicted_is_vulnerable_path_ids)
        if not self.test_run:
            json.dump(modified_sarif, open(self.posthoc_filtering_output_result_sarif_path, "w"))

        # 7. Dump the statistics
        if not self.test_run:
            stats = {
                "num_gpt_calls": num_calls,
                "num_cached": num_cached,
                "num_failure": num_failure,
                "num_vulnerable_paths": num_alerts,
            }
            json.dump(stats, open(self.posthoc_filtering_output_stats_json_path, "w"))
