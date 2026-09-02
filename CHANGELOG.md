# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project intends to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once
the first public package is released.

## [Unreleased]

### Added

- Development-ready documentation architecture.
- Product definition, feature catalog, security model, threat model, and milestone gates.
- Architecture Decision Record process.
- Contribution and private vulnerability-reporting guidance.
- Documentation quality workflow and GitHub collaboration templates.
- Strict TypeScript workspace with exact runtime and dependency pins.
- Modern-only MCP `2026-07-28` stdio compatibility probe.
- Runtime-validated zero-authority tool contract and automated compatibility tests.
- Build, format, lint, type-check, and test workflow for pull requests.
- Reproducible M0 compatibility evidence.
- Synthetic Supabase Auth, Data API, PostgreSQL RLS, revocation, audit, and catalog-policy laboratories.
- Principal/client-bound `memory_search`, `memory_get`, and `memory_list_recent` through a fixed
  read-only MCP surface with complete wire, request-ID, time, row, and concurrency bounds.
- Official Auth sign-in reuse and authenticated PostgREST OpenAPI surface census in synthetic M2.
- Environment-only verified read-only stdio startup, synthetic client example, and operator
  revoke/rollback guidance for the experimental local profile.
- Governed Artifact Inspection S0 contracts for opaque IDs, bounded operations, integrity evidence,
  receipts, deterministic profiles, and many-source derivation lineage.
- Synthetic artifact registry, approved-inspector policy, Storage RLS laboratory, and deterministic
  S1b source/chunk/Merkle calibration with mutation-sensitive proof verification.
- Synthetic/local S2 fixed artifact inspector library for stat, bounded range, and bounded UTF-8
  line reads, including strict injected-record/read validation, distinct capability-grant custody,
  exact immutable-version unavailability, redacted dependency failures, and validated immutable
  receipts.
- Optional S3 synthetic/local MCP registration for exactly `artifact_stat`, `artifact_read_range`,
  and `artifact_read_lines`, with trusted-context derivation, fixed timeout/abort handling, shared
  complete-wire containment, and a deeply frozen executable Supabase Storage closure manifest.
  Default CLI/stdio startup remains memory-only; this adds no real network/Storage adapter,
  Edge/hosted deployment, Storage/database mutation, `service_role`, signed URL, caller-selected
  coordinate, listing, ingest, semantic analysis, exact search, write, private-data, or
  production-readiness claim.
- An isolated S4 deterministic text-index primitive for in-memory UTF-8 line records and Markdown
  ATX headings, with exact source-byte offsets, fatal UTF-8 validation, bounded source/read counts,
  collision-resistant heading identifiers, fenced-code exclusion, strict consumed-index validation,
  immutable outputs, and no I/O or model execution. Inspector/MCP integration, automatic ingest, an
  approved synthetic artifact demo, exact search, and publication remain outside this primitive.

### Changed

- Reframed the README around the current Supabase hosted MCP and current MCP
  authorization requirements.

[Unreleased]: https://github.com/jryski/Supabase_user_MCP/compare/main...HEAD
