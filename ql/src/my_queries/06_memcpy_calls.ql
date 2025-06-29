/**
 * @name Chiamat4a memcpy
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/example-path
 * @problem.severity warning
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */


import cpp

from FunctionCall fc
where fc.getTarget().getName()= "memcpy"
select fc, "Trovata chiamata a memcpy"
