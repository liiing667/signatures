# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- `KGenerator::accept_context`: accept a new context (secret key, message digest and associated
  data) and start a new generation, resetting the belt-wbl state and re-deriving the belt-block
  key so stale candidates from a previous context are no longer replayed
- `KGenerator::generation`: monotonic index of the generation currently in progress

### Changed
- Generation lifecycle is now explicit: `KGenerator::new` accepts the initial context
  (generation 0), `fill_next_k` retries stay inside the current generation, and only
  `accept_context` starts a new generation. Fixed vectors and empty-context behavior are
  unchanged

### 0.1.0 (2026-08-04)
- Initial release
