# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Transactional signing index handling on `lms::SigningKey`: `reserve_index`,
  `sign_reserved`, `recover_index` and `recovered_indices`, plus a shareable
  `lms::SigningContext` snapshot for concurrent signing. Reserving an index,
  producing the OTS signature, recovering after a failed attempt and verifying
  now all revolve around the same `q` transaction, so concurrent signers never
  read the same `q` and a failed attempt neither burns nor reuses a leaf
  private key. Sequential signing behavior and the serialized key format are
  unchanged.

## 0.0.1 (2024-04-16)

- Initial release
