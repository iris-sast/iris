/** Provides taint tracking configurations to be used in Trust Manager queries. */

import java
import semmle.code.java.dataflow.FlowSources
import MyInsecureTrustManager
import MySources
import MySinks
import MySummaries


/**
 * A configuration to model the flow of an insecure `TrustManager`
 * to the initialization of an SSL context.
 */
module MyInsecureTrustManagerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { 
    //source instanceof InsecureTrustManagerSource 
    isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) { 
    //sink instanceof InsecureTrustManagerSink 
    isGPTDetectedSink(sink)
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }

  predicate allowImplicitRead(DataFlow::Node node, DataFlow::ContentSet c) {
    (isSink(node) or isAdditionalFlowStep(node, _)) and
    node.getType() instanceof Array and
    c instanceof DataFlow::ArrayContent
  }
}

module MyInsecureTrustManagerFlow = DataFlow::Global<MyInsecureTrustManagerConfig>;
