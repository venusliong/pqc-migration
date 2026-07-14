# CodeQL PQC scan report

Source: `report/openssh-codeql.sarif`  |  Findings: **30**

## Summary by rule

| Rule | Findings |
|---|---|
| pqc/legacy-crypto-api | 30 |

## Findings

| File:Line | Crypto function | Migration guidance |
|---|---|---|
| `dh.c:303` | `DH_generate_key` | Classic DH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports |
| `dh.c:317` | `DH_new` | Classic DH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports |
| `dh.c:341` | `DH_new` | Classic DH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports |
| `digest-openssl.c:59` | `EVP_md5` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| `digest-openssl.c:60` | `EVP_sha1` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| `ed25519-openssl.c:53` | `EVP_PKEY_CTX_new_id` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_ED25519: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ed25519-openssl.c:106` | `EVP_PKEY_new_raw_private_key` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_ED25519: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ed25519-openssl.c:141` | `EVP_PKEY_new_raw_private_key` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_ED25519: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ed25519-openssl.c:212` | `EVP_PKEY_new_raw_public_key` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_ED25519: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `kexdh.c:97` | `DH_compute_key` | Classic DH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports |
| `kexecdh.c:57` | `EC_KEY_new_by_curve_name` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `kexecdh.c:61` | `EC_KEY_generate_key` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `kexecdh.c:103` | `EC_KEY_new_by_curve_name` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `kexecdh.c:107` | `EC_KEY_generate_key` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `kexecdh.c:178` | `ECDH_compute_key` | ECDH is quantum-vulnerable: migrate to ML-KEM-768 (FIPS 203); hybrid X25519MLKEM768 for transports |
| `ssh-ecdsa-sk.c:330` | `ECDSA_SIG_new` | ECDSA is quantum-vulnerable: migrate to ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) for long-lived signatures |
| `ssh-ecdsa.c:175` | `EVP_PKEY_CTX_new_id` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_EC: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204)
EVP_PKEY_CTX_new_id: EVP context bound to quantum-vulnerable algorithm NID_X9_62_id_ecPublicKey: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-ecdsa.c:206` | `EC_KEY_new_by_curve_name` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `ssh-ecdsa.c:245` | `EC_KEY_new_by_curve_name` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `ssh-ecdsa.c:456` | `ECDSA_SIG_new` | ECDSA is quantum-vulnerable: migrate to ML-DSA-65 (FIPS 204); SLH-DSA (FIPS 205) for long-lived signatures |
| `ssh-keygen.c:540` | `RSA_new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-pkcs11.c:906` | `EC_KEY_new` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `ssh-pkcs11.c:1039` | `RSA_new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-rsa.c:130` | `EVP_PKEY_CTX_new_id` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_RSA: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-rsa.c:164` | `RSA_new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-rsa.c:200` | `RSA_new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-rsa.c:248` | `RSA_new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| `ssh-sk.c:221` | `EC_KEY_new_by_curve_name` | EC key material backs quantum-vulnerable ECDSA/ECDH: migrate to ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| `sshkey.c:487` | `EVP_sha1` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| `sshkey.c:3346` | `EVP_PKEY_new_raw_private_key` | EVP context bound to quantum-vulnerable algorithm EVP_PKEY_ED25519: migrate key establishment to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
