/**
 * @name Legacy algorithm name flows to EVP factory
 * @description Tracks quantum-vulnerable algorithm name strings ("RSA",
 *              "EC", ...) through variables and parameters into EVP
 *              by-name factory functions — the cross-file indirection
 *              that pattern matching cannot resolve.
 * @kind path-problem
 * @problem.severity error
 * @id pqc/algorithm-name-flow
 * @tags security cryptography quantum
 */

import cpp
import lib.CryptoConfig
import semmle.code.cpp.dataflow.new.DataFlow
import Flow::PathGraph

module AlgoNameConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    algoNameSource(_, source.asExpr().(StringLiteral).getValue())
  }

  predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall c, string name |
      algoNameFactorySink(_, name) and
      c.getTarget().getName() = name and
      sink.asExpr() = c.getArgument([1, 2])
    )
  }
}

module Flow = DataFlow::Global<AlgoNameConfig>;

from Flow::PathNode source, Flow::PathNode sink
select sink.getNode(), source, sink,
  "[P1] Quantum-vulnerable algorithm name $@ reaches an EVP factory: migrate to ML-KEM-768 (FIPS 203) for key establishment or ML-DSA-65 (FIPS 204) for signatures.",
  source.getNode(), source.getNode().asExpr().(StringLiteral).getValue()
