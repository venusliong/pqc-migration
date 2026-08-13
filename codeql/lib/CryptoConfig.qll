/**
 * Extensible predicates populated by per-library data extension files under
 * `codeql/ext/*.model.yml`. Keeps `library` as the first column of every
 * predicate so a future `ext/mbedtls.model.yml`, `ext/wolfssl.model.yml`,
 * etc. adds coverage with zero changes to the `.ql` query logic.
 */

import cpp

/** A legacy low-level crypto API call, matched by regex, with migration metadata. */
extensible predicate legacyApiPattern(
  string library, string algorithm, string pattern, string priority, string suggestion
);

/** An exact function name that is a sink for an EVP legacy-algorithm-ID macro. */
extensible predicate evpLegacyIdSinkFunction(string library, string name);

/** A regex matching macro names that expand to a legacy EVP algorithm ID. */
extensible predicate evpLegacyIdMacroPattern(string library, string pattern);

/** An exact function name (call or bare reference target) that is a weak hash. */
extensible predicate weakHashFunction(string library, string name, string suggestion);

/** An exact algorithm-name string literal that is a quantum-vulnerable EVP by-name source. */
extensible predicate algoNameSource(string library, string algorithmName);

/** An exact function name that is an EVP by-name factory sink. */
extensible predicate algoNameFactorySink(string library, string functionName);
