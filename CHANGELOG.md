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
- An S4 deterministic text-index primitive for in-memory UTF-8 line records and Markdown ATX
  headings, now exported and consumed after complete-source S1b verification by bounded line and
  heading reads. Optional artifact registration exposes exactly four fixed tools, and a hardcoded
  synthetic Markdown fixture (SHA-256
  `262e40ee94b26db00178579e911bbd532776b532e68043026560e3dce4066cf3`) passes stat, lines,
  heading, fenced/unknown denial, integrity-proof, receipt, untrusted-rendering, and closure checks
  through the real MCP Client + `StreamTransport` seam. The index is rebuilt in memory per verified
  read and is neither persisted nor published. Default CLI/stdio remains memory-only. This adds no live
  adapter, ingest persistence, derived publication, Edge/hosted deployment, Storage/database mutation,
  privileged credential, signed URL, caller-selected coordinate, listing, semantic analysis, write,
  private-data, or production claim.
- Synthetic/local S5a deterministic `artifact_search_exact` over one at-most-8,192-byte verified source,
  using case-sensitive raw UTF-8 byte matching, canonical line numbers, non-overlapping bounded hits,
  complete-source S1b integrity, content-free search receipts, and no total-count disclosure. Optional
  artifact registration now exposes exactly five artifact tools and requires an injected
  `artifact-receipt-journal/0.1`; every source-bound receipt is digest-bound and acknowledged inside the
  existing 2,000 ms deadline before MCP return. `artifact-storage-closure/0.2` records no artifact-data
  writes and only acknowledged append-only operational-evidence writes. The expanded fixed Markdown
  SDK fixture (SHA-256 `219f6d8e995539a99ffd48221e8f4357c8946f3395e03fb36f75f6d9c12c2501`)
  proves repeated ASCII/multibyte hits, a zero-hit query, proofs, inert hostile content, deterministic
  journal acknowledgements, unchanged source bytes, and content-free evidence. No persistent journal
  backend or live Storage/network adapter is included; default CLI/stdio remains memory-only. Live S5
  adoption still requires an approved real adapter and durable evidence backend, and S6 semantic
  summaries have not started. This adds no semantic/vector search, ingest, publication, hosted
  deployment, Storage/database mutation, `service_role`, signed URL, listing, caller-selected
  coordinate, canonical write, private data, or production-readiness claim.

### Changed

- Reframed the README around the current Supabase hosted MCP and current MCP
  authorization requirements.

[Unreleased]: https://github.com/jryski/Supabase_user_MCP/compare/main...HEAD
