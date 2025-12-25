# Workflow expression RCE vulnerability (fixed in v1.122.0)

## Impact
- Authenticated builders could craft workflow expressions that were evaluated as JavaScript inside the n8n runtime, leading to arbitrary code execution with the n8n process privileges.
- Successful exploitation enables full instance compromise (reading secrets, modifying workflows, executing system commands).
- Fixed upstream in n8n `v1.122.0`; instances below that version remain vulnerable.

## Why it was exploitable
- Workflow parameters accept expressions (e.g. `{{ ... }}` or `$evaluateExpression(...)`). At runtime these strings are executed through `NodeExecutionContext.evaluateExpression()` at `/home/runner/work/n8n/n8n/packages/core/src/execution-engine/node-execution-context/node-execution-context.ts#L519-L531`, which delegates to the shared expression engine.
- The evaluator runs user-controlled expressions via `Tournament.execute` in `/home/runner/work/n8n/n8n/packages/workflow/src/expression-evaluator-proxy.ts`. Before v1.122.0 the evaluation context did not fully isolate `this`, prototype chains, or access to the underlying `$` helper, so crafted payloads could reach Node.js globals (`process`, `constructor.constructor`, etc.) and achieve RCE.

## Relevant code surface
- Entry point: `evaluateExpression()` in `/home/runner/work/n8n/n8n/packages/core/src/execution-engine/node-execution-context/node-execution-context.ts#L519-L531` sends untrusted expressions to the workflow evaluator with execution data.
- Expression runtime: `/home/runner/work/n8n/n8n/packages/workflow/src/expression.ts` builds the evaluation context. Prior to the fix, insufficient guardrails allowed prototype access and `Function`-based escapes.

## Mitigations now in place (v1.122.0+)
- **AST sandbox hooks** — `/home/runner/work/n8n/n8n/packages/workflow/src/expression-evaluator-proxy.ts` wires `Tournament` with `FunctionThisSanitizer`, `PrototypeSanitizer`, and `DollarSignValidator` from `/home/runner/work/n8n/n8n/packages/workflow/src/expression-sandboxing.ts`. These hooks:
  - Rebind function `this` to an inert object to block access to Node globals.
  - Reject or sanitize prototype/property access using `isSafeObjectProperty` (e.g. forbidding `constructor`, `__proto__`, `prototype`).
  - Prevent taking a reference to the raw `$` helper to stop calling it outside the safe proxy.
- **Restricted global context** — `Expression.initializeGlobalContext()` in `/home/runner/work/n8n/n8n/packages/workflow/src/expression.ts` explicitly nulls dangerous constructors and APIs (`Function`, `eval`, timers, networking primitives) while allow-listing harmless math/date utilities, shrinking what user expressions can reach.
- **Safe property validation** — `/home/runner/work/n8n/n8n/packages/workflow/src/utils.ts#L367-L401` centralizes the denylist for unsafe keys, reused by the sandbox to block prototype pollution and runtime escapes.

## Example exploit payload (pre-fix)
On vulnerable versions, a malicious workflow field could include a JavaScript expression that pivots to the `Function` constructor through `this` and prototype access. For example, the following payload would resolve and execute with workflow privileges (shown here with the harmless effect of returning the working directory):

```text
{{ (function () { return this.constructor.constructor('return process.cwd()')() })() }}
```

Because the fix now binds `this` to an inert object, blocks unsafe properties (`constructor`, `__proto__`, `prototype`), and removes dangerous globals, this payload is rejected under v1.122.0+.

## Recommendations
- Upgrade all deployments to `v1.122.0` or later so the sandboxing and global restrictions above are applied.
- Until upgraded, limit workflow creation/editing to trusted operators and run n8n with least OS/network privileges (short-term mitigation from the advisory).
- After upgrading, consider rotating credentials that may have been exposed on vulnerable instances.
