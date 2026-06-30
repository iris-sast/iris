# Contributing to CWE-Bench-Java

Projects in CWE-Bench-Java follow a strict framework in how they are recorded. All projects should be logged in `project_info.csv`, `build_info.csv`, and `fix_info.csv`. Details on how each should be formatted are below.

---

## `project_info.csv`

All fields must be filled out. 

* The `project_slug` consists of: `[github_username]__[github_repository_name]_[cve_id]_[github_tag]`. 
* If there are multiple fix commits, separate them via **semicolons** (`;`). 
* If the commit exists in multiple branches, choose the branch closest to `main`.

## `build_info.csv`

Please include a single tested build configuration for each project. Do not include the project if it cannot be built using one of the included systems (Maven, Gradle, or Gradle Wrapper).

## `fix_info.csv`

Each row in this file represents a **single changed method**. Include every method for a project that fits the following criteria: 

1.  An existing method is changed (a method is not purely added or removed). 
2.  The method is related to the patch. 

> **Note:** If a project has no such methods, do not include it. Line numbers should align with the fixed version, including whitespace and closing brackets.
