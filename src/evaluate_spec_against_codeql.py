import os
import argparse
import sys
import yaml
import csv
import json
from tqdm import tqdm
from src.config import CODEQL_QUERY_VERSION

THIS_SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
NEUROSYMSA_ROOT_DIR = os.path.abspath(f"{THIS_SCRIPT_DIR}/../../")
sys.path.append(NEUROSYMSA_ROOT_DIR)

from src.config import CODEQL_DIR, OUTPUT_DIR
from src.queries import QUERIES

YAML_DIR = f"{CODEQL_DIR}/qlpacks/codeql/java-all/{CODEQL_QUERY_VERSION}/ext"

SINK_KIND = {
  "022": ["path-injection"],
  "078": ["command-injection"],
  "079": ["html-injection", "js-injection"],
  "094": ["template-injection"]
}

def extensible_model(model):
  if model == "sinkModel": return "sink"
  elif model == "sourceModel": return "source"
  else: return "none"

def get_all_codeql_specs(query):
  cwe_id = QUERIES[query]["cwe_id"]
  storage = {}

  for yml_file_name in tqdm(list(os.listdir(YAML_DIR)), desc="Loading CodeQL Yamls"):
    if not yml_file_name.endswith(".model.yml"):
      continue
    package = ".".join(yml_file_name.split(".")[:-2])
    content = yaml.safe_load(open(f"{YAML_DIR}/{yml_file_name}"))
    extensions = content["extensions"]
    for extension in extensions:
      ext = extension["addsTo"]["extensible"]
      kind = extensible_model(ext)
      data = extension["data"]
      for api in data:
        if ext == "summaryModel" or ext == "neutralModel":
          api_package = api[0]
          clazz = api[1]
          method = api[2]
        elif ext == "sinkModel":
          api_package = api[0]
          clazz = api[1]
          method = api[3]
          sink_kind = api[7]
        elif ext == "sourceModel":
          api_package = api[0]
          clazz = api[1]
          method = api[3]
        item = (api_package, clazz, method)
        if ext == "sinkModel":
          if sink_kind in SINK_KIND[cwe_id]:
            storage[item] = "sink"
          else:
            storage[item] = "none"
        else:
          storage[item] = kind

  return storage

def load_all_llm_specs(query, run_id, llm):
  cwe_id = QUERIES[query]["cwe_id"]
  labels_dir = f"{OUTPUT_DIR}/common/{run_id}/cwe-{cwe_id}/api_labels_{llm}.json"
  labels_json = json.load(open(labels_dir))
  labels = {}
  for item in labels_json:
    package = item["package"]
    clazz = item["class"]
    method = item["method"]
    llm_label = item["type"]
    labels[(package, clazz, method)] = llm_label
  return labels

def find_intersection(codeql_specs, llm_labels):
  intersection = {}
  for (sig, label) in codeql_specs.items():
    if sig in llm_labels:
      intersection[sig] = {
        "codeql_label": label,
        "llm_label": llm_labels[sig],
      }
  return intersection

def evaluate(intersection):
  kind_id = {"none": 0, "source": 1, "sink": 2, "taint-propagator": 0, "propagator": 0, "unknown": 0, "other": 0}
  array = [[0, 0, 0], [0, 0, 0], [0, 0, 0]]
  results = [[[], [], []], [[], [], []], [[], [], []]]
  for (sig, labels) in intersection.items():
    codeql_label = labels["codeql_label"]
    llm_label = labels["llm_label"]
    array[kind_id[codeql_label]][kind_id[llm_label]] += 1
    results[kind_id[codeql_label]][kind_id[llm_label]].append(sig)

  print(array[0])
  print(array[1])
  print(array[2])

  total = sum([sum(row) for row in array])
  diagonal = sum([array[i][i] for i in range(3)])
  accuracy = diagonal / total
  source_recall = 1 if sum(array[1]) == 0 else array[1][1] / sum(array[1])
  sink_recall = 1 if sum(array[2]) == 0 else array[2][2] / sum(array[2])
  print(f"Total: {total}, Accuracy: {accuracy:.4f}, Source Recall: {source_recall:.4f}, Sink Recall: {sink_recall:.4f}")

  return results

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("query")
  parser.add_argument("run_id")
  parser.add_argument("llm")
  args = parser.parse_args()

  codeql_specs = get_all_codeql_specs(args.query)
  # print(f"#specs: {len(codeql_specs)}")
  llm_specs = load_all_llm_specs(args.query, args.run_id, args.llm)
  # print(f"#llm_specs: {len(llm_specs)}")
  intersection = find_intersection(codeql_specs, llm_specs)
  # print(f"#intersections: {len(intersection)}")
  results = evaluate(intersection)

  print("false negative sources", results[1][0])
  print("false negative sinks", results[2][0])
