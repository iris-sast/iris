/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/my-path-injection-sinks-only
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

 import java
 import semmle.code.java.security.PathCreation
 import MyTaintedPathQuery
 import MyTaintedPathFlowSinksOnly::PathGraph 
 /**
  * Gets the data-flow node at which to report a path ending at `sink`.
  *
  * Previously this query flagged alerts exclusively at `PathCreation` sites,
  * so to avoid perturbing existing alerts, where a `PathCreation` exists we
  * continue to report there; otherwise we report directly at `sink`.
  */
 DataFlow::Node getReportingNode(DataFlow::Node sink) {
  MyTaintedPathFlowSinksOnly::flowTo(sink) and
   if exists(PathCreation pc | pc.getAnInput() = sink.asExpr())
   then result.asExpr() = any(PathCreation pc | pc.getAnInput() = sink.asExpr())
   else result = sink
 }
 
 from MyTaintedPathFlowSinksOnly::PathNode source, MyTaintedPathFlowSinksOnly::PathNode sink
 where MyTaintedPathFlowSinksOnly::flowPath(source, sink)
 select getReportingNode(sink.getNode()), source, sink, "This path depends on a $@.",
   source.getNode(), "user-provided value"
 