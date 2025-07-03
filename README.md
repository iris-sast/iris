# IRIS 
IRIS is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. IRIS uses LLMs to generate source and sink specifications and to filter false positive vulnerable paths. 

- [Workflow](#workflow)
- [Dataset](#dataset)
- [Results](#results)
- [Environment Setup](#environment-setup)
- [Quickstart](#quickstart)
- [Supported CWEs](#supported-cwes)
- [Supported Models](#supported-models)
- [Adding CWEs](docs/adding_cwes.md)
- [Contributing](#contributing-and-feedback)
- [Citation](#citation)
- [Team](#team)

## Workflow

At a high level, IRIS takes a project and a CWE (vulnerability class, such as path traversal vulnerability or CWE-22) as input, statically analyzes the project, and outputs a set of potential vulnerabilities (of type CWE) in the project. To achieve this, IRIS takes the following steps:

![iris workflow](iris_arch.png)

1. First we create CodeQL queries to collect external APIs in the project and all internal function parameters. 
2. We use an LLM to classify the external APIs as potential sources, sinks, or taint propagators. In another query, we use an LLM to classify the internal function parameters as potential sources. We call these taint specifications.
3. Using the taint specifications from step 2, we build a project-specific and cwe-specific (e.g., for CWE 22) CodeQL query. 
4. Then we run the query to find vulnerabilities in the given project and post-process the results. 
5. We provide the LLM the post-processed results to filter out false positives and determine whether a CWE is detected.  

## Dataset 
We have curated a dataset of Java projects, containing 120 real-world previously known vulnerabilities across 4 popular vulnerability classes. The dataset is also available to use with the Hugging Face datasets library. 

[CWE-Bench-Java](https://github.com/iris-sast/cwe-bench-java)

[CWE-Bench-Java on Hugging Face](https://huggingface.co/datasets/iris-sast/CWE-Bench-Java)

## Results

Results on the effectiveness of IRIS across 121 projects and 9 LLMs can be found at `/results`. Each model has a unique CSV file, with the following structure as an example.

| CWE ID | CVE | Author | Package | Tag | Recall | Alerts | Paths | TP Alerts | TP Paths | Precision | F1 |
| -- | ------------ | ------ | -------|----------|-----------------|------------------------|------------|------------|-------------|-----------------|----------------|
| CWE-022 | CVE-2016-10726 | DSpace | DSpace | 4.4 | 0 | 31 | 63 | 0 | 0 | 0 | 0 |

`None` refers to data that was not collected, while `N/A` refers to a measure that cannot be calculated, either because of missing data or a division by zero.

## Environment Setup

You can set up IRIS either 1) using Docker on any system or 2) step-by-step on your own for Mac or Linux.

### Using Docker (Recommended)

```bash
docker build -f Dockerfile --platform linux/x86_64 -t iris:latest .
docker run --platform=linux/amd64 -it iris:latest
```

Note: Read the instructions for "Native Setup" below if you intend to configure Java build tools (JDK, Maven, Gradle) or CodeQL.

### Native Setup (Mac/Linux)

#### Step 1: Setup Conda environment

```sh
conda env create -f environment.yml
conda activate iris
```

If you have a CUDA-capable GPU and want to enable hardware acceleration, install the appropriate CUDA toolkit, for example:
```bash
$ conda install pytorch-cuda=12.1 -c nvidia -c pytorch
```
Replace 12.1 with the CUDA version compatible with your GPU and drivers, if needed.

#### Step 2: Configure Java build tools

To apply IRIS to Java projects, you need to specify the paths to your Java build tools (JDK, Maven, Gradle) in the `dep_configs.json` file in the project root.

The versions of these tools required by each project are specified in `data/build_info.csv`. For instance, `perwendel__spark_CVE-2018-9159_2.7.1` requires JDK 8 and Maven 3.5.0. You can install and manage these tools easily using [SDKMAN!](https://sdkman.io/).

```sh
# Install SDKMAN!
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"

# Install Java 8 and Maven 3.5.0
sdk install java 8.0.452-amzn
sdk install maven 3.5.0
```

#### Step 3: Configure CodeQL

IRIS relies on the CodeQL Action bundle, which includes CLI utilities and pre-defined queries for various CWEs and languages ("QL packs").

If you already have CodeQL installed, specify its location via the `CODEQL_DIR` environment variable in `src/config.py`. Otherwise, download an appropriate version of the CodeQL Action bundle from the [CodeQL Action releases page](https://github.com/github/codeql-action/releases).

- **For the latest version:**
  Visit the [latest release](https://github.com/github/codeql-action/releases/latest) and download the appropriate bundle for your OS:
  - `codeql-bundle-osx64.tar.gz` for macOS
  - `codeql-bundle-linux64.tar.gz` for Linux

- **For a specific version (e.g., 2.15.0):**
  Go to the [CodeQL Action releases page](https://github.com/github/codeql-action/releases), find the release tagged `codeql-bundle-v2.15.0`, and download the appropriate bundle for your platform.

After downloading, extract the archive in the project root directory:

```sh
tar -xzf codeql-bundle-<platform>.tar.gz
```

This should create a sub-directory `codeql/` with the executable `codeql` inside.

Lastly, add the path of this executable to your `PATH` environment variable:

```sh
export PATH="$PWD/codeql:$PATH"
```

**Note:** Also adjust the environment variable `CODEQL_QUERY_VERSION` in `src/config.py` according to the instructions therein. For instance, for CodeQL v2.15.0, this should be `0.8.0`.

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

## Supported CWEs
Here are the following CWEs supported, that you can specify as an argument to `--query` when using `src/iris.py`. 

- `cwe-022wLLM` - [CWE-022](https://cwe.mitre.org/data/definitions/22.html) (Path Traversal)
- `cwe-078wLLM` - [CWE-078](https://cwe.mitre.org/data/definitions/78.html) (OS Command Injection)
- `cwe-079wLLM` - [CWE-079](https://cwe.mitre.org/data/definitions/79.html) (Cross-Site Scripting)
- `cwe-089wLLM` - [CWE-089](https://cwe.mitre.org/data/definitions/89.html) (SQL Injection)
- `cwe-094wLLM` - [CWE-094](https://cwe.mitre.org/data/definitions/94.html) (Code Injection)
- `cwe-295wLLM` - [CWE-295](https://cwe.mitre.org/data/definitions/295.html) (Improper Certificate Validation)
- `cwe-352wLLM` - [CWE-352](https://cwe.mitre.org/data/definitions/352.html) (Cross-Site Request Forgery)
- `cwe-502wLLM` - [CWE-502](https://cwe.mitre.org/data/definitions/502.html) (Deserialization of Untrusted Data)
- `cwe-611wLLM` - [CWE-611](https://cwe.mitre.org/data/definitions/611.html) (Improper Restriction of XML External Entity Reference)
- `cwe-807wLLM` - [CWE-807](https://cwe.mitre.org/data/definitions/807.html) (Reliance on Untrusted Inputs in a Security Decision)
- `cwe-918wLLM` - [CWE-918](https://cwe.mitre.org/data/definitions/918.html) (Server-Side Request Forgery)

## Supported Models
We support the following models with our models API wrapper (found in `src/models`) in the project. Listed below are the arguments you can use for `--llm` when using `src/iris.py`. You're free to use your own way of instantiating models or adding on to the existing library. Some of them require your own API key or license agreement on HuggingFace. 

<details>
  <summary>List of Models</summary>
  
### Codegen
- `codegen-16b-multi`
- `codegen25-7b-instruct`
- `codegen25-7b-multi`

### Codellama
#### Standard Models
- `codellama-70b-instruct`
- `codellama-34b`
- `codellama-34b-python`
- `codellama-34b-instruct`
- `codellama-13b-instruct`
- `codellama-7b-instruct`

### CodeT5p
- `codet5p-16b-instruct`
- `codet5p-16b`
- `codet5p-6b`
- `codet5p-2b`

### DeepSeek
- `deepseekcoder-33b`
- `deepseekcoder-7b`
- `deepseekcoder-v2-15b`

### Gemini
- `gemini-1.5-pro`
- `gemini-1.5-flash`
- `gemini-pro`
- `gemini-pro-vision`
- `gemini-1.0-pro-vision`

### Gemma
- `gemma-7b`
- `gemma-7b-it`
- `gemma-2b`
- `gemma-2b-it`
- `codegemma-7b-it`
- `gemma-2-27b`
- `gemma-2-9b`

### GPT
- `gpt-4`
- `gpt-3.5`
- `gpt-4-1106`
- `gpt-4-0613`

### LLaMA
#### LLaMA-2
- `llama-2-7b-chat`
- `llama-2-13b-chat`
- `llama-2-70b-chat`
- `llama-2-7b`
- `llama-2-13b`
- `llama-2-70b`

#### LLaMA-3
- `llama-3-8b`
- `llama-3.1-8b`
- `llama-3-70b`
- `llama-3.1-70b`
- `llama-3-70b-tai`

### Mistral
- `mistral-7b-instruct`
- `mixtral-8x7b-instruct`
- `mixtral-8x7b`
- `mixtral-8x22b`
- `mistral-codestral-22b`

### Qwen
- `qwen2.5-coder-7b`
- `qwen2.5-coder-1.5b`
- `qwen2.5-14b`
- `qwen2.5-32b`
- `qwen2.5-72b`

### StarCoder
- `starcoder`
- `starcoder2-15b`

### WizardLM
#### WizardCoder
- `wizardcoder-15b`
- `wizardcoder-34b-python`
- `wizardcoder-13b-python`

#### WizardLM Base
- `wizardlm-70b`
- `wizardlm-13b`
- `wizardlm-30b`

### Ollama

You need to install the `ollama` package manually.

- `qwen2.5-coder:latest`
- `qwen2.5:32b`
- `llama3.2:latest`
- `deepseek-r1:32b`
- `deepseek-r1:latest`

</details>

## [Adding CWEs](docs/adding_cwes.md)
We're always open to contributions of CWE we don't currently support. Refer to our [list of currently supported CWEs](#supported-cwes) to figure out what CWE can be added.  

## Contributing and Feedback
Feel free to address any open issues or add your own issue and fix. We love feedback! Please adhere to the following guidelines. 

1. Create a Github issue outlining the piece of work. Solicit feedback from anyone who has recently contributed to the component of the repository you plan to contribute to. 
2. Checkout a branch from `main` - preferably name your branch `[github username]/[brief description of contribution]`
3. Create a pull request that refers to the created github issue in the commit message.
4. To link to the github issue, in your commit for example you would simply add in the commit message:
[what the PR does briefly] #[commit issue]
5. Then when you push your commit and create your pull request, Github will automatically link the commit back to the issue. Add more details in the pull request, and request reviewers from anyone who has recently modified related code.
6. After 1 approval, merge your pull request.

## Citation 
Consider citing our paper:
```
@inproceedings{li2025iris,
title={LLM-Assisted Static Analysis for Detecting Security Vulnerabilities},
author={Ziyang Li and Saikat Dutta and Mayur Naik},
booktitle={International Conference on Learning Representations},
year={2025},
url={https://arxiv.org/abs/2405.17238}
}
```
[Arxiv Link](https://arxiv.org/abs/2405.17238)

## Team

IRIS is a collaborative effort between researchers at the University of Pennsylvania and Cornell University. Please reach out to us if you have questions about IRIS.

[Ziyang Li](https://liby99.github.io)

[Claire Wang](https://clairewang.net)

[Saikat Dutta](https://www.cs.cornell.edu/~saikatd)

[Mayur Naik](https://www.cis.upenn.edu/~mhnaik)

<img src="https://github.com/user-attachments/assets/37969a67-a3fd-4b4f-9be4-dfeed28d2b48" width="175" height="175" alt="Cornell University" />

<img src="https://github.com/user-attachments/assets/362abdfb-4ca4-46b2-b003-b185ce4d20af" width="300" height="200" alt="University of Pennsylvania"/>
