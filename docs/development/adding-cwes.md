# Adding CWEs
We are always open to supporting new CWEs. We recommend any of the CWEs in the [OWASP top 25](https://cwe.mitre.org/top25/) that we don't currently support. 

To add a CWE, you will need to provide the CodeQL queries and add the CWE queries to `queries.py`. 

Typically the structure of the queries would be
```
cwe-*
├── cwe-*wLLM.ql
│   
└── My[CodeQLCWEQueryModuleName].qll
```
`cwe-*wLLM.ql` is the wrapper query that imports the module `*.qll` file. The `*.qll` file is the module library - this is where the logic for the sources and sinks is implemented. 

1. Find the CWE definition on the [Mitre CWE site](https://cwe.mitre.org/data/definitions/502.html). A strong understanding of the CWE will help you in the following steps.
2. We recommend using CodeQL's CWE queries for examples. You can find CodeQL's CWE queries in the [CodeQL github repository](https://github.com/github/codeql). In `java/ql/src/Security/CWE`, locate the CWE you're interested in adding. Within each CWE directory, locate the `.ql` file. Often there are multiple `.ql` files - a quick heuristic is to pick the `.ql` file with the most general name, and most similar to the CWE name. 

For example - [CWE-022](https://cwe.mitre.org/data/definitions/22.html) has `TaintedPath.ql` and `ZipSlip.ql`. We used `TaintedPath.ql`. 

3. Once you've found the corresponding `.ql` file for the CWE - make note of this file. This will be the wrapper query. Within the file, there should be an import statement that refers to the module related to the CWE. Often it will be prefixed with `semmle.code.java.security` and end with `Query`. Within the CodeQL repository, find the module in `codeql/java/ql/lib/semmle/code/java/security`. 
4. Within the `cwe-queries` directory of iris, create a new folder titled `cwe-[CWE number]`. Within the folder copy the `.ql` and the `.qll` files. Rename them with the prefix `My`. Within the `.qll` file - there may be multiple modules suffixed with `Config`. Find the Config that includes the `.qll` name in it - - this is where the source and sink predicates are defined. 

Within the module, replace the predicates with the following
```
predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
 }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }
```

Also add the following imports:
```
 import MySources
 import MySinks
 import MySummaries
```

Remove the former predicate definitions and anything else in the file related to the former predicates. Now in the `.ql` file, update the imports to refer to the renamed `.qll` module.

5. Now within the [`queries.py`](../src/queries.py) file, add the CWE and its queries to the `QUERIES` dictionary. Note - if the CWE is double digits - for the id use 0[number]. For example - CWE 22 would be `cwe-022`. Use the following format - we use CWE-22 as an example:
```
"cwe-[number]wLLM": {
    "name": "cwe-[number]wLLM",
    "type": "cwe-query",
    "cwe_id": "022",
    "cwe_id_short": "22",
    "cwe_id_tag": "CWE-22",
    "desc": "Path Traversal or Zip Slip",
    "queries": [
      "cwe-queries/cwe-022/cwe-022wLLM.ql",
      "cwe-queries/cwe-022/MyTaintedPathQuery.qll",
    ],
    "prompts": {
      "cwe_id": "CWE-022",
      "desc": "Path Traversal or Zip Slip",
      "long_desc": """\
        A path traversal vulnerability allows an attacker to access files \
        on your web server to which they should not have access. They do this by tricking either \
        the web server or the web application running on it into returning files that exist outside \
        of the web root folder. Another attack pattern is that users can pass in malicious Zip file \
        which may contain directories like "../". Typical sources of this vulnerability involves \
        obtaining information from untrusted user input through web requests, getting entry directory \
        from Zip files. Sinks will relate to file system manipulation, such as creating file, listing \
        directories, and etc.""",
      "examples": [
        {
          "package": "java.util.zip",
          "class": "ZipEntry",
          "method": "getName",
          "signature": "String getName()",
            "sink_args": [],
          "type": "source",
        },
        {
          "package": "java.io",
          "class": "FileInputStream",
          "method": "FileInputStream",
          "signature": "FileInputStream(File file)",
          "sink_args" : ["file"],
          "type": "sink",
        },
        {
          "package": "java.net",
          "class": "URL",
          "method": "URL",
          "signature": "URL(String url)",
            "sink_args": [],
          "type": "taint-propagator",
        },
        {
            "package": "java.io",
            "class": "File",
            "method": "File",
            "signature": "File(String path)",
            "sink_args": [],
          "type": "taint-propagator",
        },
      ]
    }
  },
```

For the `long_desc` key - look up definitions of the CWE and find a clear description that summarizes what the CWE is and how it's exploited. 

For the examples, you will need to provide sources and sinks. A CodeQL source is a value that an attacker can use for malicious operations within a system. A CodeQL sink is a program point that accepts a malicious source, and ends up using the malicious data. You can use the [Github Advisory Database](https://github.com/advisories) to find examples of the CWE. Or the definition may provide common abstractions which you can then search for Java's most used libraries for the related abstraction. 

6. Add a hint related to CWE for contextual analysis prompt in [`prompts.py`](../src/prompts.py). Hints are stored in `POSTHOC_FILTER_HINTS`. The key should be the CWE number and the value include sentences that describe extra details to look out for when detecting the CWE. Sites that have definitions for the CWE will often have more specific guidance on the CWE.

6. Test out the query. You can provide the --test-run parameter when running `iris.py` to see if the CodeQL queries compile. Afterwards, you can try a test run with a small model on one of the Java projects associated with the CWE. The [GitHub Advisory Database](https://github.com/advisories) is an easy way to find a vulnerable project given the CWE.
