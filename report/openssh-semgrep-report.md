# PQC migration scan report

Target: `targets/openssh-portable`  |  Findings: **33**

## Summary by priority

| Priority | Findings |
|---|---|
| P1 | 13 |
| P2 | 17 |
| P3 | 3 |

## Summary by primitive

| Primitive | Findings |
|---|---|
| EC | 14 |
| RSA | 5 |
| DH | 4 |
| EVP(id) | 3 |
| ECDSA | 3 |
| MD5/SHA1 | 3 |
| ECDH | 1 |

## Top files

| File | Findings |
|---|---|
| kexecdh.c | 5 |
| ssh-ecdsa.c | 4 |
| ssh-rsa.c | 4 |
| dh.c | 3 |
| regress/misc/sk-dummy/sk-dummy.c | 3 |
| ssh-pkcs11.c | 2 |
| regress/unittests/sshbuf/test_sshbuf_getput_crypto.c | 2 |
| digest-openssl.c | 2 |
| ed25519-openssl.c | 1 |
| kexdh.c | 1 |
| ssh-keygen.c | 1 |
| regress/misc/ssh-verify-attestation/ssh-verify-attestation.c | 1 |
| regress/unittests/sshbuf/test_sshbuf_getput_fuzz.c | 1 |
| ssh-ecdsa-sk.c | 1 |
| ssh-sk.c | 1 |

## Findings

| Priority | File:Line | Crypto function | Suggested replacement |
|---|---|---|---|
| P1 | `dh.c:303` | `DH_generate_key` | ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768 |
| P1 | `dh.c:317` | `DH_new` | ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768 |
| P1 | `dh.c:341` | `DH_new` | ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768 |
| P1 | `ed25519-openssl.c:53` | `EVP_PKEY_CTX_new_id` | ML-KEM-768 (kex/encrypt) or ML-DSA-65 (sign) |
| P1 | `kexdh.c:97` | `DH_compute_key` | ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768 |
| P1 | `kexecdh.c:178` | `ECDH_compute_key` | ML-KEM-768 (FIPS 203), hybrid X25519MLKEM768 |
| P1 | `ssh-ecdsa.c:175` | `EVP_PKEY_CTX_new_id` | ML-KEM-768 (kex/encrypt) or ML-DSA-65 (sign) |
| P1 | `ssh-keygen.c:540` | `RSA_new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `ssh-pkcs11.c:1039` | `RSA_new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `ssh-rsa.c:130` | `EVP_PKEY_CTX_new_id` | ML-KEM-768 (kex/encrypt) or ML-DSA-65 (sign) |
| P1 | `ssh-rsa.c:164` | `RSA_new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `ssh-rsa.c:200` | `RSA_new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `ssh-rsa.c:248` | `RSA_new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P2 | `kexecdh.c:57` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `kexecdh.c:61` | `EC_KEY_generate_key` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `kexecdh.c:103` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `kexecdh.c:107` | `EC_KEY_generate_key` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `regress/misc/sk-dummy/sk-dummy.c:106` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `regress/misc/sk-dummy/sk-dummy.c:110` | `EC_KEY_generate_key` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `regress/misc/sk-dummy/sk-dummy.c:367` | `ECDSA_do_sign` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `regress/misc/ssh-verify-attestation/ssh-verify-attestation.c:217` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `regress/unittests/sshbuf/test_sshbuf_getput_crypto.c:226` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `regress/unittests/sshbuf/test_sshbuf_getput_crypto.c:249` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `regress/unittests/sshbuf/test_sshbuf_getput_fuzz.c:63` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `ssh-ecdsa-sk.c:330` | `ECDSA_SIG_new` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `ssh-ecdsa.c:206` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `ssh-ecdsa.c:245` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `ssh-ecdsa.c:456` | `ECDSA_SIG_new` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `ssh-pkcs11.c:906` | `EC_KEY_new` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P2 | `ssh-sk.c:221` | `EC_KEY_new_by_curve_name` | ML-DSA-65 (sign) / ML-KEM-768 (kex) |
| P3 | `digest-openssl.c:59` | `EVP_md5` | SHA-384 or SHA3-384 |
| P3 | `digest-openssl.c:60` | `EVP_sha1` | SHA-384 or SHA3-384 |
| P3 | `sshkey.c:487` | `EVP_sha1` | SHA-384 or SHA3-384 |
