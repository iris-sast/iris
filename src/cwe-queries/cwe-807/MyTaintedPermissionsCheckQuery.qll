/** Provides classes to reason about tainted permissions check vulnerabilities. */

import java
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.TaintTracking
import MySources
import MySinks
import MySummaries

/**
 * The `org.apache.shiro.subject.Subject` class.
 */
private class TypeShiroSubject extends RefType {
  TypeShiroSubject() { this.getQualifiedName() = "org.apache.shiro.subject.Subject" }
}

/**
 * The `org.apache.shiro.authz.permission.WildcardPermission` class.
 */
private class TypeShiroWildCardPermission extends RefType {
  TypeShiroWildCardPermission() {
    this.getQualifiedName() = "org.apache.shiro.authz.permission.WildcardPermission"
  }
}

/**
 * An expression that constructs a permission.
 */
abstract class PermissionsConstruction extends Top {
  /** Gets the input to this permission construction. */
  abstract Expr getInput();
}

private class PermissionsCheckMethodCall extends MethodCall, PermissionsConstruction {
  PermissionsCheckMethodCall() {
    exists(Method m | m = this.getMethod() |
      m.getDeclaringType() instanceof TypeShiroSubject and
      m.getName() = "isPermitted"
      or
      m.getName().toLowerCase().matches("%permitted%") and
      m.getNumberOfParameters() = 1
    )
  }

  override Expr getInput() { result = this.getArgument(0) }
}

private class WildCardPermissionConstruction extends ClassInstanceExpr, PermissionsConstruction {
  WildCardPermissionConstruction() {
    this.getConstructor().getDeclaringType() instanceof TypeShiroWildCardPermission
  }

  override Expr getInput() { result = this.getArgument(0) }
}

/**
 * A configuration for tracking flow from user input to a permissions check.
 */
module MyTaintedPermissionsCheckFlowConfig implements DataFlow::ConfigSig {
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

module TaintedPermissionsCheckFlow = TaintTracking::Global<MyTaintedPermissionsCheckFlowConfig>;
