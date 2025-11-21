/** Provides a taint tracking configuration to track cross site scripting. */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking
import MyXSS

import MySources
import MySinks
import MySummaries

/**
 * A taint-tracking configuration for cross site scripting vulnerabilities.
 */
module MyXssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof XssSanitizer }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2) or
    isGPTDetectedStep(node1, node2)
  }
}

/** Tracks flow from remote sources to cross site scripting vulnerabilities. */
module MyXssFlow = TaintTracking::Global<MyXssConfig>;


module MyXssConfigSinksOnly implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ActiveThreatModelSource
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof XssSanitizer }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  }
}

/** Tracks flow from remote sources to cross site scripting vulnerabilities. */
module MyXssFlowSinksOnly = TaintTracking::Global<MyXssConfigSinksOnly>;

module MyXssConfigSourcesOnly implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof XssSink
  }

  predicate isBarrier(DataFlow::Node node) { node instanceof XssSanitizer }

  predicate isBarrierOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  }
}

/** Tracks flow from remote sources to cross site scripting vulnerabilities. */
module MyXssFlowSourcesOnly = TaintTracking::Global<MyXssConfigSourcesOnly>;
