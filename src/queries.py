"""
 Use the following format when adding a key to the QUERIES dictionary:
   "query_name": {
     "name": "",
     "type": "cwe-query",
     "cwe_id": "CWE-[CWE number]", - add 0 in front of double digit CWEs. 
     "cwe_id_short": "[CWE number]", - short version of the CWE number. Remove 0 in front of double digit CWEs.
     "cwe_id_tag": "CWE-[CWE number]", - cwe_id but without the 0 in front of double digit CWEs.
     "type": "cwe-query",
     "desc": "", - short description of the CWE
     "queries": [
       "cwe-queries/cwe-[CWE number]/cwe-[CWE number]wLLM.ql", - path to query file
       "cwe-queries/cwe-[CWE number]/*.qll" - path to  *.qll files used.
     ],
     "prompts": {
       "cwe-id": "CWE-[CWE number]" - same cwe_id as above,
       "desc": "", - same short description as above
       "long_desc": \, - long description of the CWE which includes definition and attack pattern. 
       "examples": [ - list of examples of source, sink, and taint-propagator methods.
         {
           "package": "",
           "class": "",
           "method": "",
           "signature": "",
             "sink_args": [], - name of parameter variable in the signature above 
           "type": "sink",
         },
         {
           "package": "",
           "class": "",
           "method": "",
           "signature": "",
           "type": "source",
         }
       ]
     },
 """
QUERIES = {
  "cwe-022wLLM": {
    "name": "cwe-022wLLM",
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
  "cwe-022wLLMSinksOnly": {
    "name": "cwe-022wLLMSinksOnly",
    "cwe_id": "022",
    "desc": "Path Traversal or Zip Slip",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/cwe-022/cwe-022wLLMSinksOnly.ql",
      "cwe-queries/cwe-022/MyTaintedPathQuery.qll",
    ],
  },
  "cwe-022wLLMSourcesOnly": {
    "name": "cwe-022wLLMSourcesOnly",
    "cwe_id": "022",
    "desc": "Path Traversal or Zip Slip",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/cwe-022/cwe-022wLLMSourcesOnly.ql",
      "cwe-queries/cwe-022/MyTaintedPathQuery.qll",
    ]
  },
  "cwe-022wCodeQL": {
    "name": "cwe-022wCodeQL",
    "cwe_id": "022",
    "cwe_id_short": "22",
    "cwe_id_tag": "CWE-22",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-022wCodeQLExp": {
    "name": "cwe-022wCodeQLExp",
    "cwe_id": "022",
    "cwe_id_short": "22",
    "cwe_id_tag": "CWE-22",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-078wLLM": {
    "name": "cwe-078wLLM",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "cwe-query",
    "desc": "OS Command Injection",
    "queries": [
      "cwe-queries/cwe-078/CommandInjectionRuntimeExecwLLM.ql",
      "cwe-queries/cwe-078/MyCommandInjectionRuntimeExec.qll",
      "cwe-queries/cwe-078/MyCommandArguments.qll",
      "cwe-queries/cwe-078/MyCommandLineQuery.qll",
    ],
    "prompts": {
      "cwe_id": "CWE-078",
      "desc": "OS Command Injection",
      "long_desc": """\
OS command injection is also known as shell injection. It allows an \
attacker to execute operating system (OS) commands on the server that \
is running an application, and typically fully compromise the application \
and its data. Often, an attacker can leverage an OS command injection \
vulnerability to compromise other parts of the hosting infrastructure, \
and exploit trust relationships to pivot the attack to other systems within \
the organization.""",
      "examples": [
        {
          "package": "javax.servlet.http",
          "class": "HTTPServletRequest",
          "method": "getCookies()",
          "signature": "Cookie[] getCookies()",
          "type": "source",
        },
        {
          "package": "java.lang",
          "class": "Runtime",
          "method": "exec",
          "signature": "Process exec(String[] cmdarray)",
          "sink_args": ["cmdarray"],
          "type": "sink",
        },
        {
          "package": "com.jcraft.jsch",
          "class": "ChannelExec",
          "method": "setCommand",
          "signature": "void setCommand(String command)",
          "sink_args": ["command"],
          "type": "sink",
        }
      ]
    }
  },
  "cwe-078wLLMSinksOnly": {
    "name": "cwe-078wLLMSinksOnly",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "cwe-query-ablation",
    "desc": "OS Command Injection",
    "queries": [
      "cwe-queries/cwe-078/CommandInjectionRuntimeExecwLLMSinksOnly.ql",
      "cwe-queries/cwe-078/MyCommandInjectionRuntimeExec.qll",
      "cwe-queries/cwe-078/MyCommandArguments.qll",
      "cwe-queries/cwe-078/MyCommandLineQuery.qll",
    ]
   },
    "cwe-078wLLMSourcesOnly": {
    "name": "cwe-078wLLMSourcesOnly",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "desc": "OS Command Injection",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/cwe-078/CommandInjectionRuntimeExecwLLMSourcesOnly.ql",
      "cwe-queries/cwe-078/MyCommandInjectionRuntimeExec.qll",
      "cwe-queries/cwe-078/MyCommandArguments.qll",
      "cwe-queries/cwe-078/MyCommandLineQuery.qll",
    ]
   },
  "cwe-078wCodeQL": {
    "name": "cwe-078wCodeQL",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-078wCodeQLExp": {
    "name": "cwe-078wCodeQLExp",
    "cwe_id": "078",
    "cwe_id_short": "78",
    "cwe_id_tag": "CWE-78",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-079wLLM": {
    "name": "cwe-079wLLM",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "cwe-query",
    "desc": "Cross-Site Scripting",
    "queries": [
      "cwe-queries/cwe-079/XSS.ql",
      "cwe-queries/cwe-079/MyXSS.qll",
      "cwe-queries/cwe-079/MyXssQuery.qll",
      "cwe-queries/cwe-079/MyXssLocalQuery.qll",
    ],
    "prompts": {
      "cwe-id": "CWE-079",
      "desc": "Cross-Site Scripting",
      "long_desc": """\
Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable \
scripts into the code of a trusted application or website. Attackers often initiate an XSS \
attack by sending a malicious link to a user and enticing the user to click it. If the app \
or website lacks proper data sanitization, the malicious link executes the attacker's chosen \
code on the user's system. As a result, the attacker can steal the user's active session \
cookie. Logging functions are NOT sinks for XSS attacks.""",
      "examples": [
        {
          "package": "org.apache.wicket.core.request.handler",
          "class": "IPartialPageRequestHandler",
          "method": "appendJavaScript",
          "signature": "void appendJavaScript(CharSequence seq)",
          "sink_args": ["seq"],
          "type": "sink",
        },
        {
          "package": "org.thymeleaf",
          "class": "TemplateEngine",
          "method": "process",
          "signature": "void process(String template, IContext context, Writer writer)",
          "sink_args": ["context"],
          "type": "sink",
        },
        {
          "package": "org.jboss.resteasy.spi",
          "class": "HttpRequest",
          "method": "getDecodedFormParameters",
          "signature": "MultivaluedMap<String,String> getDecodedFormParameters()",
          "type": "source",
        },
      ]
    }
  },
  "cwe-079wLLMSinksOnly": {
    "name": "cwe-079wLLMSinksOnly",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "cwe-query-ablation",
    "desc": "Cross-Site Scripting",
    "queries": [
      "cwe-queries/cwe-079/XSSSinksOnly.ql",
      "cwe-queries/cwe-079/MyXSS.qll",
      "cwe-queries/cwe-079/MyXssQuery.qll",
      "cwe-queries/cwe-079/MyXssLocalQuery.qll",
    ]
  },
  "cwe-079wLLMSourcesOnly": {
    "name": "cwe-079wLLMSourcesOnly",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "desc": "Cross-Site Scripting",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/cwe-079/XSSSourcesOnly.ql",
      "cwe-queries/cwe-079/MyXSS.qll",
      "cwe-queries/cwe-079/MyXssQuery.qll",
      "cwe-queries/cwe-079/MyXssLocalQuery.qll",
    ]
  },
  "cwe-079wCodeQL": {
    "name": "cwe-079wCodeQL",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-079wCodeQLExp": {
    "name": "cwe-079wCodeQLExp",
    "cwe_id": "079",
    "cwe_id_short": "79",
    "cwe_id_tag": "CWE-79",
    "type": "codeql-query",
    "experimental": True,
  },
  "cwe-094wLLM": {
    "name": "cwe-094wLLM",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "desc": "Code Injection",
    "type": "cwe-query",
    "queries": [
      "cwe-queries/cwe-094/SpelInjection.ql",
      "cwe-queries/cwe-094/MySpelInjection.qll",
      "cwe-queries/cwe-094/MySpelInjectionQuery.qll",
    ],
    "prompts": {
      "cwe-id": "CWE-079",
      "desc": "Code Injection",
      "long_desc": """\
Code injection is the term used to describe attacks that inject code \
into an application. That injected code is then interpreted by the \
application, changing the way a program executes. Code injection attacks \
typically exploit an application vulnerability that allows the processing \
of invalid data. This type of attack exploits poor handling of untrusted \
data, and these types of attacks are usually made possible due to a lack \
of proper input/output data validation.""",
      "examples": [
        {
          "package": "com.datastax.driver.core",
          "class": "Session",
          "method": "execute",
          "signature": "void execute(String code, Object[] args)",
          "sink_args": ["code", "args"],
          "type": "sink",
        },
        {
          "package": "org.xmlunit.xpath",
          "class": "JAXPXPathEngine",
          "method": "evaluate",
          "signature": "String evaluate(String xPath, Node n)",
          "sink_args": ["xPath"],
          "type": "sink",
        },
        {
          "package": "javax.mail.internet",
          "class": "MimeMessage",
          "method": "getAllHeaders",
          "signature": "Enumeration<Header> getAllHeaders()",
          "type": "source",
        },
      ]
    }
  },
  "cwe-094wLLMSourcesOnly": {
    "name": "cwe-094wLLMSourcesOnly",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "desc": "Code Injection",
    "type": "cwe-query-ablation",
    "queries": [
      "cwe-queries/cwe-094/SpelInjectionSourcesOnly.ql",
      "cwe-queries/cwe-094/MySpelInjection.qll",
      "cwe-queries/cwe-094/MySpelInjectionQuery.qll",
    ]
  },
   "cwe-094wLLMSinksOnly": {
    "name": "cwe-094wLLMSinksOnly",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "type": "cwe-query-ablation",
    "desc": "Code Injection",
    "queries": [
      "cwe-queries/cwe-094/SpelInjectionSinksOnly.ql",
      "cwe-queries/cwe-094/MySpelInjection.qll",
      "cwe-queries/cwe-094/MySpelInjectionQuery.qll",
    ]
  },
  "cwe-094wCodeQL": {
    "name": "cwe-094wCodeQL",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "type": "codeql-query",
    "experimental": False,
  },
  "cwe-094wCodeQLExp": {
    "name": "cwe-094wCodeQLExp",
    "cwe_id": "094",
    "cwe_id_short": "94",
    "cwe_id_tag": "CWE-94",
    "type": "codeql-query",
    "experimental": True,
  },
  "fetch_external_apis": {
    "name": "fetch_external_apis",
    "queries": [
      "queries/fetch_external_apis.ql"
    ]
  },
  "fetch_func_params": {
    "name": "fetch_func_params",
    "queries": [
      "queries/fetch_func_params.ql"
    ]
  },
  "fetch_func_locs": {
    "name": "fetch_func_locs",
    "queries": [
      "queries/fetch_func_locs.ql"
    ]
  },
  "fetch_class_locs": {
    "name": "fetch_class_locs",
    "queries": [
      "queries/fetch_class_locs.ql"
    ]
  },
  "fetch_sources": {
    "name": "fetch_sources",
    "queries": [
      "queries/fetch_sources.ql"
    ]
  },
  "fetch_sinks": {
    "name": "fetch_sinks",
    "queries": [
      "queries/fetch_sinks.ql"
    ]
  }
}
