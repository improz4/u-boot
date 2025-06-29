/**
 * @name Definizione memcpy
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/example-path
 * @problem.severity warning
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */

import cpp

from Function f
where f.getName() = "memcpy"
select f,"Trovata definizione di memcpy"
