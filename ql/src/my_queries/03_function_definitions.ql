/**
 * @name Definizione strlen
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/example-path
 * @problem.severity warning
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */

import cpp


import cpp

from Function f
where f.getName() = "strlen"
select f,"Trovata definizione di strlen"
