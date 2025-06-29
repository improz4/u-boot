/**
 * @name Invocazione macro
 * @description Esempio
 * @kind path-problem
 * @id cpp/custom/example-path
 * @problem.severity warning
 * @tags correctness
 * @precision high
 * @query.packs my-org/my-queries
 */

import cpp  

from MacroInvocation mi
where mi.getMacro().getName() in ["ntohs", "ntohl", "ntohll"]
select mi, "Trovata invocazione macro"
