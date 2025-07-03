import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import MySources
import MySinks
import MySummaries

//  Main Source: https://github.com/iris-sast/iris/blob/main/docs/adding_cwes.md

/**
 * A taint-tracking configuration that tracks data flow from user-controlled sources
 * to network request sinks without proper validation, indicating a possible SSRF.
 */
module MyRequestForgeryConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // Delegate to LLM-detected sources (for example: HttpServletRequest.getParameter, etc.)
    isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    // Delegate to LLM-detected sinks (for example: java.net.HttpURLConnection.connect, etc.)
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node sanitizer) {
    // Basic primitive / boxed / numeric types are considered barriers
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    // Allow the LLM to supplement with additional propagation steps
    isGPTDetectedStep(n1, n2)
  }
}

/** Tracks flow from user-controlled input to network request execution points. */
module MyRequestForgeryFlow = TaintTracking::Global<MyRequestForgeryConfig>; 
/** Provides taint configurations for Server-Side Request Forgery (SSRF) detection */
