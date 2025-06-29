/**
 * @name Definizione macro
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/example-path
 * @problem.severity warning
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */

import cpp

from Macro m
where m.getName() in ["ntohs","ntohl","ntohll"]
select m, "Trovata macro."
