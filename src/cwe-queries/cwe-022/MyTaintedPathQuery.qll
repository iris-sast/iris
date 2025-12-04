/** Provides dataflow configurations for tainted path queries. */

import java
import semmle.code.java.frameworks.Networking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.ExternalFlow
import semmle.code.java.security.PathSanitizer

import semmle.code.java.security.TaintedPathQuery
import MySources
import MySinks
import MySummaries

/**
 * A taint-tracking configuration for tracking flow from remote sources to the creation of a path.
 */
module MyTaintedPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
 }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType or
    sanitizer instanceof PathInjectionSanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }
}

/** Tracks flow from remote sources to the creation of a path. */
module MyTaintedPathFlow = TaintTracking::Global<MyTaintedPathConfig>;


/**
 * A taint-tracking configuration for tracking flow from remote sources to the creation of a path.
 */
module MyTaintedPathSinksOnlyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ActiveThreatModelSource
 }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType or
    sanitizer instanceof PathInjectionSanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    any(TaintedPathAdditionalTaintStep s).step(n1, n2)
  }
}

/** Tracks flow from remote sources to the creation of a path. */
module MyTaintedPathFlowSinksOnly = TaintTracking::Global<MyTaintedPathSinksOnlyConfig>;


/**
 * A taint-tracking configuration for tracking flow from remote sources to the creation of a path.
 */
module MyTaintedPathSourcesOnlyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
 }

  predicate isSink(DataFlow::Node sink) {
    sinkNode(sink, "path-injection")
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType or
    sanitizer instanceof PathInjectionSanitizer
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    any(TaintedPathAdditionalTaintStep s).step(n1, n2)
  }
}

/** Tracks flow from remote sources to the creation of a path. */
module MyTaintedPathFlowSourcesOnly = TaintTracking::Global<MyTaintedPathSourcesOnlyConfig>;
