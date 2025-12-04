/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/my-path-injection
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import java
import PathCreation
import MyTaintedPathQuery
import MyTaintedPathFlow::PathGraph

/**
 * Gets the data-flow node at which to report a path ending at `sink`.
 *
 * Previously this query flagged alerts exclusively at `PathCreation` sites,
 * so to avoid perturbing existing alerts, where a `PathCreation` exists we
 * continue to report there; otherwise we report directly at `sink`.
 */
DataFlow::Node getReportingNode(DataFlow::Node sink) {
  MyTaintedPathFlow::flowTo(sink) and
  if exists(PathCreation pc | pc.getAnInput() = sink.asExpr())
  then result.asExpr() = any(PathCreation pc | pc.getAnInput() = sink.asExpr())
  else result = sink
}

bindingset[src]
string sourceType(DataFlow::Node src) {
  if exists(Parameter p | src.asParameter() = p)
  then result = "user-provided value as public function parameter"
  else result = "user-provided value from external api return value"
}

from
  MyTaintedPathFlow::PathNode source, MyTaintedPathFlow::PathNode sink
where
  MyTaintedPathFlow::flowPath(source, sink)
select
  getReportingNode(sink.getNode()),
  source,
  sink,
  "This path depends on a $@.",
  source.getNode(),
  sourceType(source.getNode())
