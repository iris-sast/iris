<p align="center">
  <a href="http://iris-sast.github.io/iris">
    <img src="docs/assets/iris_logo.svg" style="height: 20em" alt="IRIS logo" />
  </a>
</p>
<p align="center"><strong>[&nbsp;<a href="https://iris-sast.github.io/iris/">Read the Docs</a>&nbsp;]</strong></p>

---

⚠️ Code and data for the [ICLR 2025 Paper](https://arxiv.org/pdf/2405.17238) can be found in the v1 branch, license and citation below.

## 📰 News
* **[Nov. 24, 2025]**: Updated queries to version 1.8.1 to work with CodeQL 2.23.2.
* **[Nov. 24, 2025]**: Updated the Docker integration in the main IRIS pipeline so that the container images include the project dependencies. The updated images can be found in [IRIS Docker Hub](https://hub.docker.com/r/irissast/cwe-bench-java-containers-v2).
* **[Sep. 24, 2025]**: Added Docker integration for the main IRIS pipeline, released images for 189 CWE-Bench-Java CVEs on the [IRIS Docker Hub](https://hub.docker.com/r/irissast/cwe-bench-java-containers).
* **[Aug. 30, 2025]**: Updated CWE-Bench-Java with 93 new CVEs and 38 CWEs.
* **[Jul. 10, 2025]**: IRIS v2 released, added support for 7 new CWEs.

## 👋 Overview
### IRIS
IRIS is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. IRIS uses LLMs to generate source and sink specifications and to filter false positive vulnerable paths.
At a high level, IRIS takes a project and a CWE (vulnerability class, such as path traversal vulnerability or CWE-22) as input, statically analyzes the project, and outputs a set of potential vulnerabilities (of type CWE) in the project.

![iris workflow](docs/assets/iris_arch.png)

### CWE-Bench-Java
This repository also contains the dataset CWE-Bench-Java, presented in the paper [LLM-Assisted Static Analysis for Detecting Security Vulnerabilities](https://arxiv.org/abs/2405.17238).
At a high level, this dataset contains 213 CVEs spanning 49 CWEs. Some examples include path-traversal, OS-command injection, cross-site scripting, and code-injection. Each CVE includes the buggy and fixed source code of the project, along with the information of the fixed files and functions. We provide the seed information in this repository, and we provide scripts for fetching, patching, and building the repositories. The dataset collection process is illustrated in the figure below:

![cwe-bench graphic](docs/assets/dataset-collection.png)

The table below summarizes the number of CVEs in our dataset grouped by CWE category, with smaller categories (fewer than 5 CVEs) grouped together for compactness.

| CWE-ID | CVE Count |
|--------|-----------|
| CWE-22 | 60 |
| CWE-79 | 38 |
| CWE-94 | 23 |
| CWE-78 | 13 |
| CWE-502 | 7 |
| CWE-611 | 6 |
| CWE-200 | 5 |
| CWE-287 | 5 |
| CWE-400 | 5 |
| Other CWEs (36 total) | 51 | 

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

IRIS relies on the CodeQL Action bundle, which includes CLI utilities and pre-defined queries for various CWEs and languages ("QL packs"). We suggest using CodeQL version 2.23.2.

If you already have CodeQL installed, specify its location via the `CODEQL_DIR` environment variable in `src/config.py`. Otherwise, download an appropriate version of the CodeQL Action bundle from the [CodeQL Action releases page](https://github.com/github/codeql-action/releases).

- **For the latest version:**
  Visit the [latest release](https://github.com/github/codeql-action/releases/latest) and download the appropriate bundle for your OS:
  - `codeql-bundle-osx64.tar.gz` for macOS
  - `codeql-bundle-linux64.tar.gz` for Linux

- **For a specific version (e.g., 2.23.2):**
  Go to the [CodeQL Action releases page](https://github.com/github/codeql-action/releases), find the release tagged `codeql-bundle-v2.23.2`, and download the appropriate bundle for your platform.

After downloading, extract the archive in the project root directory:

```sh
tar -xzf codeql-bundle-<platform>.tar.gz
```

This should create a sub-directory `codeql/` with the executable `codeql` inside.

Lastly, add the path of this executable to your `PATH` environment variable:

```sh
export PATH="$PWD/codeql:$PATH"
```

**Note:** Also adjust the environment variable `CODEQL_QUERY_VERSION` in `src/config.py` according to the instructions therein. For instance, for CodeQL v2.23.2, this should be `1.8.1`.

### Visualizer

IRIS comes with a visualizer to view the SARIF output files. More detailed instructions can be found in the [docs](https://iris-sast.github.io/iris/features/visualizer.html).

![iris visualizer](docs/assets/visualizer.png)

#### Usage:

1. **Configure paths**: Edit `config.json` to point to your outputs and source directories
2. **Start the server**: Run `python3 server.py`
3. **Open in browser**: Navigate to `http://localhost:8000`
4. **Select a project**: Choose a project from the dropdown to load its analysis results
5. **Filter and explore**: Use the CWE and model filters to explore specific vulnerabilities

## ⚡ Quickstart

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
Additionally, you can download an image from CWE-Bench-Java from our [Docker Hub](https://hub.docker.com/r/irissast/cwe-bench-java-containers), and use the ```--use-container``` flag to run IRIS from a Docker container. You can use this flag with other Docker images as well.

## 💫 Contributions
We welcome any contributions, pull requests, or issues!
If you would like to contribute, please either file a new pull request or issue. We'll be sure to follow up shortly!

## 🤝 Our Team

IRIS is a collaborative effort between researchers at Cornell University and the University of Pennsylvania. Please reach out to us if you have questions about IRIS.

### Students

[Claire Wang](https://clairewang.net), University of Pennsylvania

[Amartya Das](https://github.com/IcebladeLabs), Ward Melville High School

[Derin Gezgin](https://deringezgin.github.io/), Connecticut College

[Zhengdong (Forest) Huang](https://github.com/FrostyHec), Southern University of Science and Technology

[Nevena Stojkovic](https://www.linkedin.com/in/nevena-stojkovic-3b7a69335), Massachusetts Institute of Technology

### Faculty

[Ziyang Li](https://liby99.github.io), Johns Hopkins University, previously PhD student at the University of Pennsylvania

[Saikat Dutta](https://www.cs.cornell.edu/~saikatd), Cornell University

[Mayur Naik](https://www.cis.upenn.edu/~mhnaik), University of Pennsylvania

<img src="https://github.com/user-attachments/assets/37969a67-a3fd-4b4f-9be4-dfeed28d2b48" width="175" height="175" alt="Cornell University" />

<img src="https://github.com/user-attachments/assets/362abdfb-4ca4-46b2-b003-b185ce4d20af" width="300" height="200" alt="University of Pennsylvania"/>

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
