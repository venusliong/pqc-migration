/**
 * @name Quantum-vulnerable crypto API usage (Ruby)
 * @description Calls to Ruby OpenSSL/Digest APIs implementing quantum-vulnerable
 *              primitives (RSA, DSA, EC, DH) or weak legacy hashes, with the
 *              suggested post-quantum replacement.
 * @kind problem
 * @problem.severity error
 * @id pqc/ruby-legacy-crypto-api
 * @tags security cryptography quantum
 */

import codeql.ruby.AST
import codeql.ruby.ApiGraphs
import codeql.ruby.Concepts
import codeql.ruby.DataFlow
import lib.RubyCryptoConfig

/**
 * Holds if `prefix` is a configured receiver path or a `::`-prefix of one.
 * Bounds the API-graph walk below to configured paths, so it never enumerates
 * the whole graph.
 */
predicate configuredPathPrefix(string prefix) {
  rubyLegacyApiCall(_, _, prefix, _, _, _, _)
  or
  exists(string longer |
    configuredPathPrefix(longer) and
    prefix = longer.regexpCapture("(.+)::[^:]+", 1)
  )
}

/** The API-graph node for a `::`-separated constant path, e.g. `OpenSSL::PKey::RSA`. */
API::Node apiNodeForPath(string path) {
  configuredPathPrefix(path) and
  (
    not path.matches("%::%") and
    result = API::getTopLevelMember(path)
    or
    result =
      apiNodeForPath(path.regexpCapture("(.+)::([^:]+)", 1))
          .getMember(path.regexpCapture("(.+)::([^:]+)", 2))
  )
}

/** Holds if `call` passes a string argument matching `argPattern`. */
bindingset[argPattern]
predicate hasMatchingStringArgument(DataFlow::CallNode call, string argPattern) {
  exists(StringLiteral s |
    s = call.getArgument(_).asExpr().getExpr() and
    s.getConstantValue().getString().regexpMatch(argPattern)
  )
}

/**
 * A configured legacy asymmetric-crypto call: P1/P2 tiers, which no official
 * CodeQL Ruby library models (`codeql/ruby-all` has no asymmetric crypto model).
 */
predicate configuredLegacyCall(DataFlow::CallNode call, string priority, string name, string msg) {
  exists(string path, string methodPattern, string argPattern, string suggestion |
    rubyLegacyApiCall(_, _, path, methodPattern, argPattern, priority, suggestion) and
    call = apiNodeForPath(path).getAMethodCall(_) and
    call.getMethodName().regexpMatch(methodPattern) and
    (argPattern = "" or hasMatchingStringArgument(call, argPattern)) and
    name = path + "." + call.getMethodName() and
    msg = suggestion
  )
}

/**
 * A weak-hash operation, taken from the official `codeql/ruby-all` crypto
 * modeling (`OpenSSL.qll` / `frameworks/core/Digest.qll`) rather than from our
 * own rows -- it already knows MD5/SHA-1 are weak and resolves the algorithm
 * whether it is named by string or by constant. Restricted to hashing so that
 * conventionally-weak ciphers (DES, RC4) stay out of scope: they are not
 * quantum-broken, and including them would redefine the P1-P3 scale.
 */
predicate officialWeakHashCall(
  Cryptography::CryptographicOperation op, string priority, string name, string msg
) {
  op.getAlgorithm() instanceof Cryptography::HashingAlgorithm and
  op.getAlgorithm().isWeak() and
  priority = "P3" and
  name = op.getAlgorithm().getName() and
  msg =
    "MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin"
}

/** A finding from our own configured rows, keyed by the AST site reported. */
predicate configuredFinding(AstNode site, string priority, string name, string msg) {
  exists(DataFlow::CallNode call |
    call.asExpr().getExpr() = site and
    configuredLegacyCall(call, priority, name, msg)
  )
}

/** A finding from the official `codeql/ruby-all` crypto modeling. */
predicate officialFinding(AstNode site, string priority, string name, string msg) {
  exists(Cryptography::CryptographicOperation op |
    op.asExpr().getExpr() = site and
    officialWeakHashCall(op, priority, name, msg)
  )
}

// Configured rows win where they match, because they report the qualified call
// (`Digest::SHA1.hexdigest`) rather than just the algorithm name, and carry the
// explicit priority. The official model is the safety net: it contributes any
// weak-hash site the rows do not describe. Without this precedence CodeQL
// merges the two results at one location into one newline-joined message.
from AstNode site, string priority, string name, string msg
where
  configuredFinding(site, priority, name, msg)
  or
  officialFinding(site, priority, name, msg) and not configuredFinding(site, _, _, _)
select site, "[" + priority + "] " + name + ": " + msg
