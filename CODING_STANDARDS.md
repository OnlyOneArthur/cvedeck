# Coding standards

- Python 3.11+ with type annotations on public functions.
- Keep network adapters, parsing, persistence, orchestration, and presentation separate.
- Never infer missing vulnerability facts or overwrite one source's score with another source's score.
- Tests exercise public seams with synthetic fixtures and no default network dependency.
- Use bounded network timeouts/retries and independent source transactions.
- Prefer standard library facilities and focused modules over abstractions without a v0.1 requirement.
