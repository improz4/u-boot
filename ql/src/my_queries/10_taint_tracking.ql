/**
 * @name TAINT PATH PROBLEM
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/taint
 * @problem.severity critical
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists( MacroInvocation mi |
      mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and
      this = mi.getExpr()
      )
  }
}

module MyConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }
  predicate isSink(DataFlow::Node sink) {
    exists( FunctionCall fc | fc.getTarget().getName()="memcpy" and sink.asExpr() = fc.getArgument(2))
  }

    predicate isBarrierGuard(DataFlow::Node expr) {
    exists(IfStmt ifs, BinaryOperation cmp |
        cmp = ifs.getCondition().(BinaryOperation) and
        (
        cmp.getOperator() = "<=" or cmp.getOperator() = "<"
        ) and
        (
        cmp.getLeftOperand() = expr.asExpr() or
        cmp.getRightOperand() = expr.asExpr()
        ) and
        // Filtra espressioni che sembrano una validazione di lunghezza
        (
        cmp.getLeftOperand().getType().getUnspecifiedType().hasName("size_t") or
        cmp.getRightOperand().getType().getUnspecifiedType().hasName("size_t")
        )
    )
  }
}

module MyTaint = TaintTracking::Global<MyConfig>;
import MyTaint::PathGraph

from MyTaint::PathNode source, MyTaint::PathNode sink
where MyTaint::flowPath(source, sink) 
select sink, source, sink, "Network byte swap flows to memcpy"
