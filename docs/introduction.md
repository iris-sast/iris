# IRIS

IRIS is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. IRIS uses LLMs to generate source and sink specifications and to filter false positive vulnerable paths.

## Overview

At a high level, IRIS takes a project and a CWE (vulnerability class, such as path traversal vulnerability or CWE-22) as input, statically analyzes the project, and outputs a set of potential vulnerabilities (of type CWE) in the project.

![iris workflow](assets/iris_arch.png)

### Key Features

- Combines LLMs with static analysis for enhanced vulnerability detection
- Supports multiple vulnerability classes (CWEs)
- Works with various LLM models
- Provides detailed analysis and results
- Easy to set up with Docker or native installation

### Getting Started

To get started with IRIS:

1. Check out the [Environment Setup](environment-setup/docker.md) guide
2. Follow our [Quickstart](quickstart.md) tutorial
3. Learn about [Supported CWEs](features/cwes.md) and [Models](features/models.md)
4. If you are interested in contributing, read our [Guidelines](development/contributing.md)

### Resources

- [CWE-Bench-Java Repository](https://github.com/iris-sast/cwe-bench-java)
- [CWE-Bench-Java on Hugging Face](https://huggingface.co/datasets/iris-sast/CWE-Bench-Java)
- [Project Results](architecture/results.md) 
