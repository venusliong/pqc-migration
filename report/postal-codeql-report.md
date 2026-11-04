# CodeQL PQC scan report

Source: `report/postal-codeql.sarif`  |  Findings: **21**

## Summary by priority

| Priority | Findings |
|---|---|
| P1 | 11 |
| P3 | 10 |

## Summary by rule

| Rule | Findings |
|---|---|
| pqc/ruby-legacy-crypto-api | 21 |

## Findings

| Priority | File:Line | Crypto function | Migration guidance |
|---|---|---|---|
| P1 | `app/models/domain.rb:87` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `app/models/domain.rb:93` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `app/models/domain.rb:99` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `app/models/domain.rb:114` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `lib/postal/config.rb:117` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `script/generate_tls_certificate.rb:10` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `spec/lib/dkim_header_spec.rb:19` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `spec/lib/postal/signer_spec.rb:7` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `spec/lib/postal_spec.rb:9` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `spec/models/domain_spec.rb:170` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P1 | `spec/models/domain_spec.rb:180` | `OpenSSL::PKey::RSA.new` | RSA is quantum-vulnerable: migrate key transport to ML-KEM-768 (FIPS 203), signatures to ML-DSA-65 (FIPS 204) |
| P3 | `app/controllers/legacy_api/messages_controller.rb:74` | `Digest::SHA1.hexdigest` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `app/lib/smtp_server/client.rb:9` | `OpenSSL::Digest.new` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `app/lib/smtp_server/client.rb:247` | `Digest::SHA1.hexdigest` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `app/models/user_invite.rb:33` | `Digest::MD5.hexdigest` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `lib/postal/message_db/message.rb:490` | `Digest::SHA1.hexdigest` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `lib/postal/signer.rb:55` | `OpenSSL::Digest.new` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `spec/apis/legacy_api/messages/message_spec.rb:282` | `Digest::SHA1.hexdigest` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `spec/lib/postal/signer_spec.rb:59` | `OpenSSL::Digest.new` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `spec/lib/postal/signer_spec.rb:71` | `OpenSSL::Digest.new` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
| P3 | `spec/lib/smtp_server/client/auth_spec.rb:112` | `OpenSSL::Digest.new` | MD5/SHA-1 are classically broken for collisions; use SHA-384+ (or SHA3) for PQC-era margin |
