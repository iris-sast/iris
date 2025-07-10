## Results

**These results are from the ICLR 2025 version of IRIS, and do not include newly added CWEs/ projects.**

Results on the effectiveness of IRIS across 121 projects and 9 LLMs can be found at `/results`. Each model has a unique CSV file, with the following structure as an example.

| CWE ID | CVE | Author | Package | Tag | Recall | Alerts | Paths | TP Alerts | TP Paths | Precision | F1 |
| -- | ------------ | ------ | -------|----------|-----------------|------------------------|------------|------------|-------------|-----------------|----------------|
| CWE-022 | CVE-2016-10726 | DSpace | DSpace | 4.4 | 0 | 31 | 63 | 0 | 0 | 0 | 0 |

`None` refers to data that was not collected, while `N/A` refers to a measure that cannot be calculated, either because of missing data or a division by zero.
