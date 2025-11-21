/**
 * @name `TrustManager` that accepts all certificates
 * @description Trusting all certificates allows an attacker to perform a machine-in-the-middle attack.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/my-insecure-trustmanager
 * @tags security
 *       external/cwe/cwe-295
 */

 import java
 import semmle.code.java.dataflow.DataFlow
 import MyInsecureTrustManagerQuery
 import MyInsecureTrustManagerFlow::PathGraph
 
 from MyInsecureTrustManagerFlow::PathNode source, MyInsecureTrustManagerFlow::PathNode sink
 where MyInsecureTrustManagerFlow::flowPath(source, sink)
 select sink, source, sink, "This uses $@, which is defined in $@ and trusts any certificate.",
   source, "TrustManager",
   source.getNode().asExpr().(ClassInstanceExpr).getConstructedType() as type, type.getNestedName()
 
