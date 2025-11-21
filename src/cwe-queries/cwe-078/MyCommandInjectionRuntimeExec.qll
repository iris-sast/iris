import java
import semmle.code.java.frameworks.javaee.ejb.EJBRestrictions
import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.ExternalFlow
import MySources
import MySinks
import MySummaries

module MyExecUserFlowConfig implements DataFlow::ConfigSig {
  //predicate isSource(DataFlow::Node source) { source instanceof Source }
  predicate isSource(DataFlow::Node src) {
    isGPTDetectedSource(src)
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }
}

/** Tracks flow of unvalidated user input that is used in Runtime.Exec */
module MyExecUserFlow = TaintTracking::Global<MyExecUserFlowConfig>;


module MyExecUserFlowConfigSinksOnly implements DataFlow::ConfigSig {
  //predicate isSource(DataFlow::Node source) { source instanceof Source }
  predicate isSource(DataFlow::Node src) {
    src instanceof ActiveThreatModelSource
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }



  predicate isBarrier(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType
  }
}

/** Tracks flow of unvalidated user input that is used in Runtime.Exec */
module MyExecUserFlowSinksOnly = TaintTracking::Global<MyExecUserFlowConfigSinksOnly>;



module MyExecUserFlowConfigSourcesOnly implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    isGPTDetectedSource(src)
  }

  predicate isSink(DataFlow::Node sink) {
      sinkNode(sink, "command-injection")
      or
      exists(MethodCall call |
        call.getMethod() instanceof RuntimeExecMethod and
        sink.asExpr() = call.getArgument(_) and
        sink.asExpr().getType() instanceof Array
      )
  }

  // predicate isSink(DataFlow::Node sink) {
  //   exists(MethodCall call |
  //     call.getMethod() instanceof RuntimeExecMethod and
  //     sink.asExpr() = call.getArgument(_) and
  //     sink.asExpr().getType() instanceof Array
  //   )
  // }


  predicate isBarrier(DataFlow::Node node) {
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType or
    node.getType() instanceof NumberType
  }
}

/** Tracks flow of unvalidated user input that is used in Runtime.Exec */
module MyExecUserFlowSourcesOnly = TaintTracking::Global<MyExecUserFlowConfigSourcesOnly>;

// array[3] = node
class AssignToNonZeroIndex extends DataFlow::Node {
  AssignToNonZeroIndex() {
    exists(AssignExpr assign, ArrayAccess access |
      assign.getDest() = access and
      access.getIndexExpr().(IntegerLiteral).getValue().toInt() != 0 and
      assign.getSource() = this.asExpr()
    )
  }
}

// String[] array = {"a", "b, "c"};
class ArrayInitAtNonZeroIndex extends DataFlow::Node {
  ArrayInitAtNonZeroIndex() {
    exists(ArrayInit init, int index |
      init.getInit(index) = this.asExpr() and
      index != 0
    )
  }
}

// Stream.concat(Arrays.stream(array_1), Arrays.stream(array_2))
class StreamConcatAtNonZeroIndex extends DataFlow::Node {
  StreamConcatAtNonZeroIndex() {
    exists(MethodCall call, int index |
      call.getMethod().getQualifiedName() = "java.util.stream.Stream.concat" and
      call.getArgument(index) = this.asExpr() and
      index != 0
    )
  }
}

// list of executables that execute their arguments
// TODO: extend with data extensions
class UnSafeExecutable extends string {
  bindingset[this]
  UnSafeExecutable() {
    this.regexpMatch("^(|.*/)([a-z]*sh|javac?|python.*|perl|[Pp]ower[Ss]hell|php|node|deno|bun|ruby|osascript|cmd|Rscript|groovy)(\\.exe)?$") and
    not this = "netsh.exe"
  }
}
