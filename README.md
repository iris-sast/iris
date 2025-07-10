<p align="center">
  <a href="http://iris-sast.github.io/iris">
    <img src="docs/assets/iris_logo.svg" style="height: 20em" alt="IRIS logo" />
  </a>
</p>
<p align="center"><strong>[&nbsp;<a href="https://iris-sast.github.io/iris/">Read the Docs</a>&nbsp;]</strong></p>

---

⚠️ Code and data for the following works can be found in the v1 branch:
* [ICLR 2025] <a href="https://arxiv.org/pdf/2405.17238">IRIS: LLM-ASSISTED STATIC ANALYSIS FOR DETECTING SECURITY VULNERABILITIES</a>

## 👋 Overview
### IRIS
IRIS is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. IRIS uses LLMs to generate source and sink specifications and to filter false positive vulnerable paths.
At a high level, IRIS takes a project and a CWE (vulnerability class, such as path traversal vulnerability or CWE-22) as input, statically analyzes the project, and outputs a set of potential vulnerabilities (of type CWE) in the project.

![iris workflow](docs/assets/iris_arch.png)

### CWE-Bench-Java
This repository also contains the dataset CWE-Bench-Java, presented in the paper [LLM-Assisted Static Analysis for Detecting Security Vulnerabilities](https://arxiv.org/abs/2405.17238).
At a high level, this dataset contains 120 CVEs spanning 4 CWEs, namely path-traversal, OS-command injection, cross-site scripting, and code-injection. Each CVE includes the buggy and fixed source code of the project, along with the information of the fixed files and functions. We provide the seed information in this repository, and we provide scripts for fetching, patching, and building the repositories. The dataset collection process is illustrated in the figure below:

![cwe-bench graphic](docs/assets/dataset-collection.png)

## 🚀 Set Up
### Using Docker (Recommended)
```bash
docker build -f Dockerfile --platform linux/x86_64 -t iris:latest .
docker run --platform=linux/amd64 -it iris:latest
```
If you intend to configure build tools (Java, Maven, or Gradle) or CodeQL, follow the native setup instructions below.
### Native (Mac/ Linux)
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

## 💫 Contributions
We welcome any contributions, pull requests, or issues!
If you would like to contribute, please either file a new pull request or issue. We'll be sure to follow up shortly!

## ✍️ Citation & license
MIT license. Check `LICENSE.md`.

If you find our work helpful, please consider citing our ICLR'25 paper:

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
