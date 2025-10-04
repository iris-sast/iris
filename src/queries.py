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
  "cwe-089wLLM": {
    "name": "cwe-089wLLM",
    "cwe_id": "089",
    "cwe_id_short": "89",
    "cwe_id_tag": "CWE-89",
    "type": "cwe-query",
    "desc": "SQL Injection via string concatenation",
    "queries": [
      "cwe-queries/cwe-089/cwe-089wLLM.ql",
      "cwe-queries/cwe-089/MySqlInjectionQuery.qll",
      "cwe-queries/cwe-089/MySqlConcatenatedLib.qll"
      ],
    "prompts": {
      "cwe_id": "CWE-089",
      "desc": "SQL Injection via string concatenation",
      "long_desc": """\
SQL Injection is a critical vulnerability that arises when user input is used to construct SQL queries without proper validation. \
This allows attackers to inject malicious SQL code into the query, bypass authentication, retrieve sensitive data, \
or execute arbitrary commands on the database server.\
This vulnerability occurs when applications dynamically build SQL strings using input from sources such as HTTP request parameters \
without using parameterized queries or prepared statements. Attackers can exploit this to perform unauthorized reads, data modification, or denial of service.
To address SQL injection, use parameterized queries, prepared statements, etc. Input validation, \
least privilege database access, and error message suppression are also important secondary defenses.
      """,
      "examples": [
        {
          "package": "javax.servlet.http",
          "class": "HttpServletRequest",
          "method": "getParameter",
          "signature": "String getParameter(String name)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "java.sql",
          "class": "Statement",
          "method": "execute",
          "signature": "boolean execute(String sql)",
          "sink_args": ["sql"],
          "type": "sink"
        },
        {
          "package": "java.sql",
          "class": "Statement",
          "method": "executeQuery",
          "signature": "ResultSet executeQuery(String sql)",
          "sink_args": ["sql"],
          "type": "sink"
        },
        {
          "package": "java.lang",
          "class": "StringBuilder",
          "method": "append",
          "signature": "StringBuilder append(String str)",
          "sink_args": [],
          "type": "taint-propagator"
        }
      ]
    }
  },
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
  "cwe-502wLLM": {
    "name": "cwe-502wLLM",
    "type": "cwe-query",
    "cwe_id": "502",
    "cwe_id_short": "502",
    "cwe_id_tag": "CWE-502",
    "desc": "Deserialization of Untrusted Data",
    "queries": [
      "cwe-queries/cwe-502/MyUnsafeDeserialization.ql",
      "cwe-queries/cwe-502/MyUnsafeDeserializationQuery.qll"
    ],
    "prompts": {
      "cwe_id": "CWE-502",
      "desc": "Deserialization of Untrusted Data",
      "long_desc": """\
        Deserialization of untrusted data occurs when an application deserializes input \
        without validating its origin or ensuring the safety of its content. An attacker \
        can exploit this to instantiate unexpected classes, invoke arbitrary methods, \
        or even trigger code execution via malicious object graphs or gadget chains. \
        This can lead to serious consequences such as unauthorized access, data corruption, \
        or remote code execution. Common mitigation strategies include using class allowlists, \
        avoiding unnecessary deserialization, making sensitive fields transient, and validating \
        object types before deserializing.""",
      "examples": [
        {
          "package": "java.io",
          "class": "ObjectInputStream",
          "method": "readObject",
          "signature": "Object readObject()",
          "sink_args": [],
          "type": "sink"
        },
        {
          "package": "java.io",
          "class": "ByteArrayInputStream",
          "method": "ByteArrayInputStream",
          "signature": "ByteArrayInputStream(byte[] buf)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "java.beans",
          "class": "XMLDecoder",
          "method": "readObject",
          "signature": "Object readObject()",
          "sink_args": [],
          "type": "sink"
        },
        {
          "package": "org.apache.commons.lang3",
          "class": "SerializationUtils",
          "method": "deserialize",
          "signature": "<T> T deserialize(byte[] objectData)",
          "sink_args": ["objectData"],
          "type": "sink"
        }
      ]
    }
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
  "cwe-918wLLM": {
    "name": "cwe-918wLLM",
    "cwe_id": "918",
    "cwe_id_short": "918",
    "cwe_id_tag": "CWE-918",
    "type": "cwe-query",
    "desc": "Server-Side Request Forgery (SSRF)",
    "queries": [
      "cwe-queries/cwe-918/cwe-918wLLM.ql",
      "cwe-queries/cwe-918/MyRequestForgeryQuery.qll"
    ],
    "prompts": {
      "cwe_id": "CWE-918",
      "desc": "Server-Side Request Forgery (SSRF)",
      "long_desc": """\
Server-Side Request Forgery (SSRF) occurs when an application makes a network request
using a URL or host that is fully or partially controlled by user input. Attackers
can abuse this to make the server perform HTTP(S) or other protocol requests to
internal services, cloud metadata endpoints, or arbitrary external servers. This
can lead to sensitive information disclosure, port scanning, or further
pivoting within the infrastructure. Properly validate and sanitize any user
input that influences outbound request destinations, and employ allow-lists
or network egress filtering where possible.""",
      "examples": [
        {
          "package": "javax.servlet.http",
          "class": "HttpServletRequest",
          "method": "getParameter",
          "signature": "String getParameter(String name)",
          "type": "source"
        },
        {
          "package": "org.apache.http.client",
          "class": "HttpClient",
          "method": "execute",
          "signature": "HttpResponse execute(HttpUriRequest request)",
          "sink_args": ["request"],
          "type": "sink"
        },
        {
          "package": "java.net",
          "class": "URL",
          "method": "URL",
          "signature": "URL(String spec)",
          "type": "taint-propagator"
        }
      ]
    }
  },
"cwe-807wLLM": {
    "name": "cwe-807wLLM",
    "type": "cwe-query",
    "cwe_id": "807",
    "cwe_id_short": "807",
    "cwe_id_tag": "CWE-807",
    "desc": "Reliance on Untrusted Inputs in a Security Decision",
    "queries": [
        "cwe-queries/cwe-807/cwe-807wLLM.ql",
        "cwe-queries/cwe-807/MyTaintedPermissionsCheckQuery.qll",
    ],
    "prompts": {
        "cwe_id": "CWE-807",
        "desc": "Reliance on Untrusted Inputs in a Security Decision",
        "long_desc": """\
CWE-807 refers that the product uses a protection mechanism that relies on the existence or values of an input, but the input can be modified by an untrusted actor in a way that bypasses the protection mechanism. If permission checks (such as Subject.isPermitted or similar APIs) receive tainted data, attackers may manipulate permission strings or resource identifiers to escalate privileges or access unauthorized resources. Sources are typically user-provided values (e.g., HTTP parameters), and sinks are permission check methods or constructors that determine access control.
""",
        "examples": [
            {
                "package": "javax.servlet.http",
                "class": "HttpServletRequest",
                "method": "getParameter",
                "signature": "String getParameter(String name)",
                "sink_args": [],
                "type": "source"
            },
            {
                "package": "org.apache.shiro.subject",
                "class": "Subject",
                "method": "isPermitted",
                "signature": "boolean isPermitted(String permission)",
                "sink_args": ["permission"],
                "type": "sink"
            },
            {
            "package": "java.util",
            "class": "HashMap",
            "method": "putAll",
            "signature": "void putAll(Map<? extends K,? extends V> m)",
            "propagator_args": ["m"],
            "type": "propagator"
            }
        ]
    }
},
"cwe-352wLLM": {
  "name": "cwe-352wLLM",
  "type": "cwe-query",
  "cwe_id": "352",
  "cwe_id_short": "352",
  "cwe_id_tag": "CWE-352",
  "desc": "Cross-Site Request Forgery",
  "queries": [
    "cwe-queries/cwe-352/cwe-352wLLM.ql",
    "cwe-queries/cwe-352/MyJsonpInjectionLib.qll",
    "cwe-queries/cwe-352/MyJsonStringLib.qll",
  ],
  "prompts": {
    "cwe_id": "CWE-352",
    "desc": "Cross-Site Request Forgery (JSONP Injection)",
    "long_desc": """\
A Cross-Site Request Forgery (CSRF) vulnerability allows attackers to perform unauthorized actions on behalf of authenticated users. 
In Java web applications, insecure JSONP endpoints may be abused for CSRF or data exfiltration attacks if the callback parameter is not properly validated. 
Sources typically include untrusted HTTP request parameters (such as 'callback'). Sinks are points where JSONP responses are constructed and returned to the client without validation.""",
    "examples": [
      {
        "package": "javax.servlet.http",
        "class": "HttpServletRequest",
        "method": "getParameter",
        "signature": "String getParameter(String name)",
        "sink_args": [],
        "type": "source",
      },
      {
        "package": "javax.servlet.http",
        "class": "HttpServletResponse",
        "method": "getWriter",
        "signature": "PrintWriter getWriter()",
        "sink_args": [],
        "type": "sink",
      },
      {
        "package": "org.json",
        "class": "JSONObject",
        "method": "toString",
        "signature": "String toString()",
        "sink_args": [],
        "type": "taint-propagator",
      },
    ]
  }
},
"cwe-611wLLM": {
    "name": "cwe-611wLLM",
    "type": "cwe-query",
    "cwe_id": "611",
    "cwe_id_short": "611",
    "cwe_id_tag": "CWE-611",
    "desc": "Improper Restriction of XML External Entity Reference",
    "queries": [
      "cwe-queries/cwe-611/XXE.ql",
      "cwe-queries/cwe-611/MyXxeRemoteQuery.qll",
      "cwe-queries/cwe-611/MyXxeQuery.qll",
      "cwe-queries/cwe-611/MyXxe.qll"
    ],
    "prompts": {
      "cwe_id": "CWE-611",
      "desc": "Improper Restriction of XML External Entity Reference",
      "long_desc": """\
        XML documents optionally contain a Document Type Definition (DTD), which, among other features, enables the definition of XML entities. It is possible to define an entity by providing a substitution string in the form of a URI. The XML parser can access the contents of this URI and embed these contents back into the XML document for further processing. \
By submitting an XML file that defines an external entity with a file:// URI, an attacker can cause the processing application to read the contents of a local file. For example, a URI such as "file:///c:/winnt/win.ini" designates (in Windows) the file C:\Winnt\win.ini, or file:///etc/passwd designates the password file in Unix-based systems. Using URIs with other schemes such as http://, the attacker can force the application to make outgoing requests to servers that the attacker cannot reach directly, which can be used to bypass firewall restrictions or hide the source of attacks such as port scanning.\
Once the content of the URI is read, it is fed back into the application that is processing the XML. This application may echo back the data (e.g. in an error message), thereby exposing the file contents.""",
      "examples": [ 
        {
          "package": "javax.xml.transform",
          "class": "DefaultDDFFileValidator",
          "method": "validate",
          "signature": "void validate(Source xmlToValidate)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "java.xml.parsers.DocumentBuilderFactory",
          "class": "DOMWalker",
          "method": "",
          "signature": "Object readObject()",
          "sink_args": [],
          "type": "sink"
        }, 
      ]
    }
  },
  "cwe-295wLLM": {
    "name": "cwe-295wLLM",
    "type": "cwe-query",
    "cwe_id": "295",
    "cwe_id_short": "295",
    "cwe_id_tag": "CWE-295",
    "desc": "Improper Certificate Validation",
    "queries": [
      "cwe-queries/cwe-295/InsecureTrustManager.ql",
      "cwe-queries/cwe-295/MyInsecureTrustManager.qll",
      "cwe-queries/cwe-295/MyInsecureTrustManagerQuery.qll",
    ],
    "prompts": {
      "cwe_id": "CWE-295",
      "desc": "Improper Certificate Validation",
      "long_desc": """\
      When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client. The product might connect to a malicious host while believing it is a trusted host, or the product might be deceived into accepting spoofed data that appears to originate from a trusted host.""",
      "examples": [ 
        {
          "package": "org.keycloak.authentication.AuthenticationFlowContext",
          "class": "ValidateX509CertificateUsername",
          "method": "authenticate",
          "signature": "void authenticate(AuthenticationFlowContext context)",
          "sink_args": [],
          "type": "source"
        },
        {
          "package": "com.tigervnc.rfb",
          "class": "CSecurityTLS",
          "method": "checkServerTrusted",
          "signature": "checkServerTrusted(X509Certificate[] chain, String authType)",
          "sink_args": ["chain", "authType"],
          "type": "sink"
        }, 
      ]
    }
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
