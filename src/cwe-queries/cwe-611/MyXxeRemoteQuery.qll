/** Provides taint tracking configurations to be used in remote XXE queries. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.TaintTracking
private import MyXxeQuery
import MySources 
import MySinks
import MySummaries

/**
 * A taint-tracking configuration for unvalidated remote user input that is used in XML external entity expansion.
 */
module MyXxeConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
     //src instanceof ThreatModelFlowSource
     isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) { 
    //sink instanceof XxeSink 
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) { 
    sanitizer instanceof XxeSanitizer 
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }
}

/**
 * Detect taint flow of unvalidated remote user input that is used in XML external entity expansion.
 */
module MyXxeFlow = TaintTracking::Global<MyXxeConfig>;
