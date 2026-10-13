# Synthetic fixtures

The gate tests generate synthetic Git repositories and credential-shaped tokens
at runtime. No recognized credential fixture is committed. All private-pattern
tests use a synthetic sentinel and replace the caller's pattern environment.
The benign contact fixture uses the reserved `example.invalid` domain.

Set `LEAK_TEST_GITLEAKS` to a trusted, checksum-verified Gitleaks 8.30.1 executable
to include the real scanner acceptance test. An omitted executable produces an
explicit skipped test, never a claim that real scanner integration passed.
