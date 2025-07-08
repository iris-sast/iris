<p align="center">
  <a href="http://iris-sast.github.io/iris">
    <img src="docs/assets/iris_logo.svg" style="height: 20em" alt="IRIS logo" />
  </a>
</p>
<p align="center"><strong>[&nbsp;<a href="https://iris-sast.github.io/iris/">Read the Docs</a>&nbsp;]</strong></p>

---

Code and data for the following works can be found in the v1 branch:
* [ICLR 2025] <a href="https://arxiv.org/pdf/2405.17238">IRIS: LLM-ASSISTED STATIC ANALYSIS FOR DETECTING SECURITY VULNERABILITIES</a>

## 👋 Overview
IRIS is a neurosymbolic framework that combines LLMs with static analysis for security vulnerability detection. IRIS uses LLMs to generate source and sink specifications and to filter false positive vulnerable paths.
At a high level, IRIS takes a project and a CWE (vulnerability class, such as path traversal vulnerability or CWE-22) as input, statically analyzes the project, and outputs a set of potential vulnerabilities (of type CWE) in the project.

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
