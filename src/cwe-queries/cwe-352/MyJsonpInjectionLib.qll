import java
private import MyJsonStringLib
private import semmle.code.java.security.XSS
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.dataflow.FlowSources
import MySources
import MySinks
import MySummaries

/**
 * A concatenate expression using `(` and `)` or `);`.
 *
 * E.g: `functionName + "(" + json + ")"` or `functionName + "(" + json + ");"`
 */
class JsonpBuilderExpr extends AddExpr {
  JsonpBuilderExpr() {
    this.getRightOperand().(CompileTimeConstantExpr).getStringValue().regexpMatch("\\);?") and
    this.getLeftOperand()
        .(AddExpr)
        .getLeftOperand()
        .(AddExpr)
        .getRightOperand()
        .(CompileTimeConstantExpr)
        .getStringValue() = "("
  }

  /** Get the jsonp function name of this expression. */
  Expr getFunctionName() {
    result = this.getLeftOperand().(AddExpr).getLeftOperand().(AddExpr).getLeftOperand()
  }

  /** Get the json data of this expression. */
  Expr getJsonExpr() { result = this.getLeftOperand().(AddExpr).getRightOperand() }
}

/** A data flow configuration tracing flow from threat model sources to jsonp function name. */
module MyThreatModelFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { 
    isGPTDetectedSource(source) 
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }
}

module MyThreatModelFlow = DataFlow::Global<MyThreatModelFlowConfig>;

/** A data flow configuration tracing flow from json data into the argument `json` of JSONP-like string `someFunctionName + "(" + json + ")"`. */
module JsonDataFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { 
    isGPTDetectedSource(source)  
  }

  predicate isSink(DataFlow::Node sink) {
    exists(JsonpBuilderExpr jhe | jhe.getJsonExpr() = sink.asExpr())
  }
}

module JsonDataFlow = DataFlow::Global<JsonDataFlowConfig>;

/** Taint-tracking configuration tracing flow from probable jsonp data with a user-controlled function name to an outgoing HTTP entity. */
module MyJsonpInjectionFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { 
    isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) { 
    isGPTDetectedSink(sink) 
  }
}

module MyJsonpInjectionFlow = TaintTracking::Global<MyJsonpInjectionFlowConfig>;

/** Taint-tracking configuration tracing flow from get method request sources to output jsonp data. */
module MyRequestResponseFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isGPTDetectedSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }

   predicate isBarrier(DataFlow::Node sanitizer) {
    sanitizer.getType() instanceof BoxedType or
    sanitizer.getType() instanceof PrimitiveType or
    sanitizer.getType() instanceof NumberType
  }
}

module MyRequestResponseFlow = TaintTracking::Global<MyRequestResponseFlowConfig>;
