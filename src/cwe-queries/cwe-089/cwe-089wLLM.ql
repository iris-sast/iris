// cwe-089wLLM.ql
/**
 * @name Query built by concatenation with a possibly-untrusted string
 * @description Building a SQL or Java Persistence query by concatenating a possibly-untrusted string
 *              is vulnerable to insertion of malicious code.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id java/my-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 */


import java
import MySqlInjectionQuery
import MySqlInjectionFlow::PathGraph

from
  MySqlInjectionFlow::PathNode source,
  MySqlInjectionFlow::PathNode sink
where
  MySqlInjectionFlow::flowPath(source, sink)
select
  sink.getNode(),
  source,
  sink,
  "SQL query built using $@, which may be tainted.",
  source.getNode(),
  "user-provided value"
