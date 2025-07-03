/**
 * @name JSONP Injection
 * @description User-controlled callback function names that are not verified are vulnerable
 *              to jsonp injection attacks.
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @id java/my-jsonp-injection
 * @tags security
 *       experimental
 *       external/cwe/cwe-352
 */

// Query Source: https://github.com/github/codeql/blob/main/java/ql/src/experimental/Security/CWE/CWE-352/JsonpInjection.ql

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.deadcode.WebEntryPoints
import semmle.code.java.security.XSS
import MyJsonpInjectionLib
import MyRequestResponseFlow::PathGraph

from MyRequestResponseFlow::PathNode source, MyRequestResponseFlow::PathNode sink
where MyRequestResponseFlow::flowPath(source, sink) and
      MyJsonpInjectionFlow::flowTo(sink.getNode())
select sink.getNode(), source, sink, "Jsonp response might include code from $@.",
       source.getNode(), "this user input"
