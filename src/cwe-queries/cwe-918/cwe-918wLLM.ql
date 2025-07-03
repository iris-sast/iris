/**
 * @name Server-side request forgery
 * @description Making web requests based on unvalidated user-input
 *              may cause the server to communicate with malicious servers.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id java/my-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

//  Query Source: https://github.com/github/codeql/blob/main/java/ql/src/Security/CWE/CWE-918/RequestForgery.ql

import java
import MyRequestForgeryQuery
import MyRequestForgeryFlow::PathGraph

from MyRequestForgeryFlow::PathNode source, MyRequestForgeryFlow::PathNode sink
where MyRequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential server-side request forgery due to a $@.",
  source.getNode(), "user-provided value"
