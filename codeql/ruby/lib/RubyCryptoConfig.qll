/**
 * Extensible predicates populated by per-library data extension files under
 * `codeql/ruby/ext/*.model.yml`, mirroring the C side's
 * `codeql/cpp/lib/CryptoConfig.qll`.
 *
 * Ruby crypto is reached through constant paths (`OpenSSL::PKey::RSA.new`)
 * rather than flat function names, so the C `pattern` column splits into
 * `receiverPath` (an exact `::` path, walked through the API graph) and
 * `methodPattern` (a regex on the method name). `argPattern`, when non-empty,
 * additionally requires a string argument matching it -- that is how a digest
 * named at the call site (`OpenSSL::Digest.new("SHA1")`) is told apart from a
 * strong one (`"SHA256"`).
 *
 * Language-neutral: the query imports its own language library.
 */

/** A legacy crypto API call on a constant path, with migration metadata. */
extensible predicate rubyLegacyApiCall(
  string library, string algorithm, string receiverPath, string methodPattern,
  string argPattern, string priority, string suggestion
);
