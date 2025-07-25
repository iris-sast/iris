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
