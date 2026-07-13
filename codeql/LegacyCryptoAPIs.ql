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

/** Maps a legacy API function-name regex to a PQC migration suggestion. */
predicate legacyApi(string rx, string suggestion) {
  rx = "RSA_(new|generate_key(_ex)?|sign|verify|(public|private)_(en|de)crypt)" and
  suggestion = "RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204)"
  or
  rx = "DSA_(new|generate_key|generate_parameters_ex|(do_)?(sign|verify))" and
  suggestion = "DSA is quantum-vulnerable: migrate to ML-DSA-65 (FIPS 204)"
  or
  rx = "ECDSA_((do_)?(sign|verify)|SIG_new)" and
  suggestion = "ECDSA is quantum-vulnerable: migrate to ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) for long-lived signatures"
  or
  rx = "ECDH_compute_key" and
  suggestion = "ECDH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports"
  or
  rx = "DH_(new|generate_key|compute_key(_padded)?|generate_parameters_ex)" and
  suggestion = "Classic DH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports"
  or
  rx = "EC_KEY_(new(_by_curve_name)?|generate_key)" and
  suggestion = "EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex)"
}

/** A call to a low-level legacy crypto API. */
predicate directLegacyCall(FunctionCall c, string msg) {
  exists(string rx | legacyApi(rx, msg) | c.getTarget().getName().regexpMatch(rx))
}

/**
 * An EVP context/keygen call whose algorithm argument comes from a
 * quantum-vulnerable EVP_PKEY_* macro (macros expand to plain NID
 * integers, invisible to text matching once behind another macro
 * or constant).
 */
predicate evpLegacyIdCall(FunctionCall c, string msg) {
  c.getTarget().getName() = ["EVP_PKEY_CTX_new_id", "EVP_PKEY_set_type", "EVP_PKEY_new_raw_private_key", "EVP_PKEY_new_raw_public_key"] and
  exists(MacroInvocation mi |
    mi.getExpr() = c.getArgument(0) and
    mi.getMacroName().regexpMatch("EVP_PKEY_(RSA(_PSS)?|EC|DSA|DH|ED25519|ED448|X25519|X448)|NID_X9_62_id_ecPublicKey") and
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
    f.getName() = ["EVP_md5", "EVP_sha1", "MD5", "MD5_Init", "SHA1", "SHA1_Init"] and
    name = f.getName() and
    msg = "MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin"
  )
}

from Expr e, string name, string msg
where
  (
    exists(FunctionCall c | c = e and directLegacyCall(c, msg) and name = c.getTarget().getName())
    or
    exists(FunctionCall c | c = e and evpLegacyIdCall(c, msg) and name = c.getTarget().getName())
    or
    weakHashUse(e, name, msg)
  ) and
  e.getFile().fromSource()
select e, name + ": " + msg
