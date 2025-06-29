/**
 * @name Esempio classe
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/example-path
 * @problem.severity warning
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */

import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    exists( MacroInvocation mi |
      mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"] and
      mi.getExpr() = this
      )
  }
}

from NetworkByteSwap n
select n, "Network byte swap"
