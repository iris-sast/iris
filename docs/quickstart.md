## Quickstart

Make sure you have followed all of the environment setup instructions before proceeding!

To quickly try IRIS on the example project `perwendel__spark_CVE-2018-9159_2.7.1`, run the following commands:

```sh
# Build the project
python scripts/fetch_and_build.py --filter perwendel__spark_CVE-2018-9159_2.7.1

# Generate the CodeQL database
python scripts/build_codeql_dbs.py --project perwendel__spark_CVE-2018-9159_2.7.1

# Run IRIS analysis
python src/iris.py --query cwe-022wLLM --run-id test --llm qwen2.5-coder-7b perwendel__spark_CVE-2018-9159_2.7.1
```

This will build the project, generate the CodeQL database, and analyze it for CWE-022 vulnerabilities using the specified LLM (qwen2.5-coder-7b). The output of these three steps will be stored under `data/build-info/`, `data/codeql-dbs/`, and `output/` respectively.
