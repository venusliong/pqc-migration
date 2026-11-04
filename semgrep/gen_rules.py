#!/usr/bin/env python3
"""Generate semgrep/rules/<language>-legacy-crypto.yaml from crypto-functions.yaml.

One rules file is written per language found in the rule specs below
(currently c-legacy-crypto.yaml and ruby-legacy-crypto.yaml).

Do not hand-edit the generated rules files -- edit crypto-functions.yaml
instead (function/pattern lists), or the specs here (message/severity/
metadata/language), then re-run this script.
"""
import yaml
from pathlib import Path

HERE = Path(__file__).resolve().parent
FUNCTIONS = yaml.safe_load((HERE / "crypto-functions.yaml").read_text())

# Fixed per-rule logic: message/severity/metadata never move to the data file.
SIMPLE_RULES = [
    dict(id="c-openssl-dh-key-agreement", severity="ERROR",
         message="Classic Diffie-Hellman key agreement ($FN) is quantum-vulnerable. "
                  "Migrate to ML-KEM-768 (FIPS 203); for TLS/SSH transports prefer a "
                  "hybrid group such as X25519MLKEM768 / mlkem768x25519-sha256.",
         category="key-exchange", primitive="DH",
         pqc_replacement="ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768", priority="P1"),
    dict(id="c-openssl-ecdh-key-agreement", severity="ERROR",
         message="ECDH key agreement ($FN) is quantum-vulnerable (Shor). Migrate to "
                  "ML-KEM-768 (FIPS 203); for transports prefer hybrid X25519MLKEM768.",
         category="key-exchange", primitive="ECDH",
         pqc_replacement="ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768", priority="P1"),
    dict(id="c-openssl-rsa-lowlevel", severity="ERROR",
         message="Low-level RSA API ($FN) is quantum-vulnerable. For key transport / "
                  "encryption migrate to ML-KEM-768 (FIPS 203, KEM-DEM); for signatures "
                  "migrate to ML-DSA-65 (FIPS 204).",
         category="rsa", primitive="RSA",
         pqc_replacement="ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign)", priority="P1"),
    dict(id="c-openssl-ecdsa-signature", severity="ERROR",
         message="ECDSA signature API ($FN) is quantum-vulnerable. Migrate to ML-DSA-65 "
                  "(FIPS 204); use SLH-DSA (FIPS 205) for long-lived/firmware signatures.",
         category="signature", primitive="ECDSA",
         pqc_replacement="ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)", priority="P2"),
    dict(id="c-openssl-dsa-signature", severity="ERROR",
         message="DSA ($FN) is quantum-vulnerable and deprecated classically. Migrate to "
                  "ML-DSA-65 (FIPS 204).",
         category="signature", primitive="DSA",
         pqc_replacement="ML-DSA-65 (FIPS 204)", priority="P2"),
    dict(id="c-openssl-ec-key", severity="WARNING",
         message="EC key management ($FN) backs quantum-vulnerable ECDSA/ECDH usage. "
                  "Migrate signatures to ML-DSA-65 (FIPS 204) and key agreement to "
                  "ML-KEM-768 (FIPS 203).",
         category="ec-key", primitive="EC",
         pqc_replacement="ML-DSA-65 (sign) / ML-KEM-768 (kex)", priority="P2"),
    dict(id="c-openssl-weak-hash", severity="WARNING",
         message="Weak/legacy hash ($FN). MD5 and SHA-1 are classically broken for "
                  "collisions; for PQC-era margin use SHA-256 minimum, SHA-384+ preferred.",
         category="hash", primitive="MD5/SHA1",
         pqc_replacement="SHA-384 or SHA3-384", priority="P3"),
    # --- Ruby: OpenSSL stdlib + Digest (same P1-P3 scale as the C rules) ---
    dict(id="ruby-openssl-rsa", language="ruby", severity="ERROR",
         message="Ruby OpenSSL RSA key operation ($FN) is quantum-vulnerable. For key "
                  "transport / encryption migrate to ML-KEM-768 (FIPS 203, KEM-DEM); for "
                  "signatures migrate to ML-DSA-65 (FIPS 204).",
         category="rsa", primitive="RSA",
         pqc_replacement="ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign)", priority="P1"),
    dict(id="ruby-openssl-dh-key-agreement", language="ruby", severity="ERROR",
         message="Classic Diffie-Hellman key agreement ($FN) is quantum-vulnerable. "
                  "Migrate to ML-KEM-768 (FIPS 203); for TLS transports prefer a hybrid "
                  "group such as X25519MLKEM768.",
         category="key-exchange", primitive="DH",
         pqc_replacement="ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768", priority="P1"),
    dict(id="ruby-openssl-ec-key", language="ruby", severity="WARNING",
         message="EC key management ($FN) backs quantum-vulnerable ECDSA/ECDH usage. "
                  "Migrate signatures to ML-DSA-65 (FIPS 204) and key agreement to "
                  "ML-KEM-768 (FIPS 203).",
         category="ec-key", primitive="EC",
         pqc_replacement="ML-DSA-65 (sign) / ML-KEM-768 (kex)", priority="P2"),
    dict(id="ruby-openssl-dsa", language="ruby", severity="ERROR",
         message="DSA ($FN) is quantum-vulnerable and deprecated classically. Migrate to "
                  "ML-DSA-65 (FIPS 204).",
         category="signature", primitive="DSA",
         pqc_replacement="ML-DSA-65 (FIPS 204)", priority="P2"),
    dict(id="ruby-openssl-signature", language="ruby", severity="ERROR",
         message="Signature operation ($FN) on an OpenSSL key or X.509 certificate is "
                  "quantum-vulnerable when the key is RSA/EC/DSA. Migrate to ML-DSA-65 "
                  "(FIPS 204); use SLH-DSA (FIPS 205) for long-lived signatures.",
         category="signature", primitive="Sign/Verify",
         pqc_replacement="ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205)", priority="P2"),
    dict(id="ruby-openssl-weak-hash", language="ruby", severity="WARNING",
         message="Weak/legacy hash ($FN). MD5 and SHA-1 are classically broken for "
                  "collisions; for PQC-era margin use SHA-256 minimum, SHA-384+ preferred.",
         category="hash", primitive="MD5/SHA1",
         pqc_replacement="SHA-384 or SHA3-384", priority="P3"),
]

EVP_ID_RULE = dict(id="c-openssl-evp-legacy-alg-id", severity="ERROR",
    message="EVP keygen/context bound to quantum-vulnerable algorithm ID ($ALG). "
             "Migrate RSA/EC/DSA/DH usage to ML-KEM-768 (FIPS 203) for key "
             "establishment or ML-DSA-65 (FIPS 204) for signatures.",
    category="evp", primitive="EVP(id)",
    pqc_replacement="ML-KEM-768 (kex/encrypt) or ML-DSA-65 (sign)", priority="P1")

EVP_NAME_RULE = dict(id="c-openssl-evp-legacy-alg-name", severity="ERROR",
    message="EVP keygen by algorithm name string ($ALG) selects a quantum-vulnerable "
             "algorithm. Migrate to ML-KEM-768 (FIPS 203) for key establishment or "
             "ML-DSA-65 (FIPS 204) for signatures.",
    category="evp", primitive="EVP(name)",
    pqc_replacement="ML-KEM-768 (kex/encrypt) or ML-DSA-65 (sign)", priority="P1")


RUBY_WEAK_HASH_NAME_RULE = dict(id="ruby-openssl-weak-hash-byname", language="ruby",
    severity="WARNING",
    message="Digest selected by algorithm name string ($ALG) is a weak/legacy hash. "
             "MD5 and SHA-1 are classically broken for collisions; for PQC-era margin "
             "use SHA-256 minimum, SHA-384+ preferred.",
    category="hash", primitive="MD5/SHA1(name)",
    pqc_replacement="SHA-384 or SHA3-384", priority="P3")

# Rules whose algorithm arrives as a name string, matched with metavariable-regex.
BYNAME_RULES = [EVP_NAME_RULE, RUBY_WEAK_HASH_NAME_RULE]


def base_rule(spec: dict) -> dict:
    return {
        "id": spec["id"],
        "languages": [spec.get("language", "c")],
        "severity": spec["severity"],
        "message": spec["message"],
        "metadata": {
            "category": spec["category"],
            "primitive": spec["primitive"],
            "pqc_replacement": spec["pqc_replacement"],
            "priority": spec["priority"],
        },
    }


def build_simple_rule(spec: dict) -> dict:
    rule = base_rule(spec)
    patterns = FUNCTIONS[spec["id"]]
    rule["patterns"] = [
        {"pattern-either": [{"pattern": p} for p in patterns]},
    ]
    return rule


def build_evp_id_rule(spec: dict) -> dict:
    rule = base_rule(spec)
    data = FUNCTIONS[spec["id"]]
    rule["patterns"] = [
        {"pattern-either": [{"pattern": p} for p in data["sink_patterns"]]},
        {"metavariable-pattern": {
            "metavariable": "$ALG",
            "pattern-either": [{"pattern": v} for v in data["alg_values"]],
        }},
    ]
    return rule


def build_byname_rule(spec: dict) -> dict:
    rule = base_rule(spec)
    data = FUNCTIONS[spec["id"]]
    rule["patterns"] = [
        {"pattern-either": [{"pattern": p} for p in data["sink_patterns"]]},
        {"metavariable-regex": {
            "metavariable": "$ALG",
            "regex": data["alg_regex"],
        }},
    ]
    return rule


def main() -> None:
    rules = [build_simple_rule(spec) for spec in SIMPLE_RULES]
    rules.append(build_evp_id_rule(EVP_ID_RULE))
    rules += [build_byname_rule(spec) for spec in BYNAME_RULES]

    by_language: dict[str, list] = {}
    for rule in rules:
        by_language.setdefault(rule["languages"][0], []).append(rule)
    for language, language_rules in by_language.items():
        out = HERE / "rules" / f"{language}-legacy-crypto.yaml"
        out.write_text(yaml.dump({"rules": language_rules}, sort_keys=False, width=100))
        print(f"wrote {out} ({len(language_rules)} rules)")


if __name__ == "__main__":
    main()
