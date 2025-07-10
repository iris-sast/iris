## Workflow

IRIS accepts a codebase and a CWE (Common Weakness Enumeration) as input, and uses a neurosymbolic approach to identify security vulnerabilities of type CWE in the project. To acheieve this, IRIS uses the following steps:

![iris workflow](../assets/iris_arch.png)

1. First we create CodeQL queries to collect external APIs in the project and all internal function parameters. 
2. We use an LLM to classify the external APIs as potential sources, sinks, or taint propagators. In another query, we use an LLM to classify the internal function parameters as potential sources. We call these taint specifications.
3. Using the taint specifications from step 2, we build a project-specific and cwe-specific (e.g., for CWE 22) CodeQL query. 
4. Then we run the query to find vulnerabilities in the given project and post-process the results. 
5. We provide the LLM the post-processed results to filter out false positives and determine whether a CWE is detected.  
