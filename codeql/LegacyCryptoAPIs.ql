/**
 * @name Quantum-vulnerable crypto API usage
 * @description Calls to OpenSSL APIs implementing quantum-vulnerable
 *              primitives (RSA, DSA, ECDSA, ECDH, DH), including EVP
 *              contexts bound to legacy algorithm IDs via macros.
 * @kind problem
 * @problem.severity error
 * @id pqc/legacy-crypto-api
 * @tags security cryptography quantum
 */

import cpp
import lib.CryptoConfig

/** A call to a low-level legacy crypto API. */
predicate directLegacyCall(FunctionCall c, string priority, string msg) {
  exists(string pattern |
    legacyApiPattern(_, _, pattern, priority, msg) and
    c.getTarget().getName().regexpMatch(pattern)
  )
}

/**
 * An EVP context/keygen call whose algorithm argument comes from a
 * quantum-vulnerable EVP_PKEY_* macro (macros expand to plain NID
 * integers, invisible to text matching once behind another macro
 * or constant).
 */
predicate evpLegacyIdCall(FunctionCall c, string msg) {
  exists(string name | evpLegacyIdSinkFunction(_, name) | c.getTarget().getName() = name) and
  exists(MacroInvocation mi, string pattern |
    mi.getExpr() = c.getArgument(0) and
    // outermost matching macro only: EVP_PKEY_EC expands to
    // NID_X9_62_id_ecPublicKey, which would double-report the same site
    not mi.getParentInvocation().getExpr() = c.getArgument(0) and
    evpLegacyIdMacroPattern(_, pattern) and
    mi.getMacroName().regexpMatch(pattern) and
    msg = "EVP context bound to quantum-vulnerable algorithm " + mi.getMacroName() +
      ": migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204)"
  )
}

/**
 * A weak-hash use: calls and bare function references alike
 * (e.g. `EVP_md5` in a digest dispatch table).
 */
predicate weakHashUse(Expr e, string name, string msg) {
  exists(Function f |
    f = e.(FunctionCall).getTarget() or
    f = e.(FunctionAccess).getTarget()
  |
    weakHashFunction(_, f.getName(), msg) and
    name = f.getName()
  )
}

from Expr e, string name, string priority, string msg
where
  (
    exists(FunctionCall c | c = e and directLegacyCall(c, priority, msg) and name = c.getTarget().getName())
    or
    exists(FunctionCall c |
      c = e and evpLegacyIdCall(c, msg) and name = c.getTarget().getName() and priority = "P1"
    )
    or
    weakHashUse(e, name, msg) and priority = "P3"
  ) and
  e.getFile().fromSource()
select e, "[" + priority + "] " + name + ": " + msg
