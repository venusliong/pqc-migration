# PQC migration scan report

Target: `targets/postal`  |  Findings: **30**

## Summary by priority

| Priority | Findings |
|---|---|
| P1 | 11 |
| P2 | 9 |
| P3 | 10 |

## Summary by primitive

| Primitive | Findings |
|---|---|
| RSA | 11 |
| Sign/Verify | 9 |
| MD5/SHA1 | 5 |
| MD5/SHA1(name) | 5 |

## Top files

| File | Findings |
|---|---|
| spec/lib/postal/signer_spec.rb | 8 |
| app/models/domain.rb | 4 |
| lib/postal/signer.rb | 3 |
| script/generate_tls_certificate.rb | 2 |
| spec/models/domain_spec.rb | 2 |
| app/lib/smtp_server/client.rb | 2 |
| lib/postal/config.rb | 1 |
| spec/lib/dkim_header_spec.rb | 1 |
| spec/lib/postal_spec.rb | 1 |
| app/lib/dkim_header.rb | 1 |
| app/controllers/legacy_api/messages_controller.rb | 1 |
| app/models/user_invite.rb | 1 |
| lib/postal/message_db/message.rb | 1 |
| spec/apis/legacy_api/messages/message_spec.rb | 1 |
| spec/lib/smtp_server/client/auth_spec.rb | 1 |

## Findings

| Priority | File:Line | Crypto function | Suggested replacement |
|---|---|---|---|
| P1 | `app/models/domain.rb:87` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `app/models/domain.rb:93` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `app/models/domain.rb:99` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `app/models/domain.rb:114` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `lib/postal/config.rb:117` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `script/generate_tls_certificate.rb:10` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `spec/lib/dkim_header_spec.rb:19` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `spec/lib/postal/signer_spec.rb:7` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `spec/lib/postal_spec.rb:9` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `spec/models/domain_spec.rb:170` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P1 | `spec/models/domain_spec.rb:180` | `RSA.new` | ML-KEM-768 (encrypt/transport) or ML-DSA-65 (sign) |
| P2 | `app/lib/dkim_header.rb:127` | `@dkim_key.sign` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `lib/postal/signer.rb:32` | `private_key.sign` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `lib/postal/signer.rb:55` | `private_key.sign` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `script/generate_tls_certificate.rb:23` | `cert.sign` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `spec/lib/postal/signer_spec.rb:26` | `signer.sign` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `spec/lib/postal/signer_spec.rb:28` | `STATIC_PRIVATE_KEY.public_key.verify` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `spec/lib/postal/signer_spec.rb:40` | `STATIC_PRIVATE_KEY.public_key.verify` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `spec/lib/postal/signer_spec.rb:59` | `STATIC_PRIVATE_KEY.public_key.verify` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P2 | `spec/lib/postal/signer_spec.rb:71` | `STATIC_PRIVATE_KEY.public_key.verify` | ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205) |
| P3 | `app/controllers/legacy_api/messages_controller.rb:74` | `Digest::SHA1.hexdigest` | SHA-384 or SHA3-384 |
| P3 | `app/lib/smtp_server/client.rb:9` | `Digest.new` | SHA-384 or SHA3-384 |
| P3 | `app/lib/smtp_server/client.rb:247` | `Digest::SHA1.hexdigest` | SHA-384 or SHA3-384 |
| P3 | `app/models/user_invite.rb:33` | `Digest::MD5.hexdigest` | SHA-384 or SHA3-384 |
| P3 | `lib/postal/message_db/message.rb:490` | `Digest::SHA1.hexdigest` | SHA-384 or SHA3-384 |
| P3 | `lib/postal/signer.rb:55` | `Digest.new` | SHA-384 or SHA3-384 |
| P3 | `spec/apis/legacy_api/messages/message_spec.rb:282` | `Digest::SHA1.hexdigest` | SHA-384 or SHA3-384 |
| P3 | `spec/lib/postal/signer_spec.rb:59` | `Digest.new` | SHA-384 or SHA3-384 |
| P3 | `spec/lib/postal/signer_spec.rb:71` | `Digest.new` | SHA-384 or SHA3-384 |
| P3 | `spec/lib/smtp_server/client/auth_spec.rb:112` | `HMAC.hexdigest` | SHA-384 or SHA3-384 |
