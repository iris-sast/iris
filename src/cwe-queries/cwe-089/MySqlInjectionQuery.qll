// MySqlInjectionQuery.qll
/**
 * Provides taint configurations for SQL Injection detection
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import MySqlConcatenatedLib
import MySources
import MySinks
import MySummaries

module MySqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
 }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }
}

module MySqlInjectionFlow = TaintTracking::Global<MySqlInjectionConfig>;
