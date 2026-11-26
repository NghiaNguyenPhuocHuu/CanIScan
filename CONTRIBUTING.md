# Contributing

Thanks for helping make AI agents safer! The project is small and has no dependencies on purpose. Here is how it fits together.

## Architecture

```
discovery.py   find candidate files (project walk + known user-level paths)
parsers.py     load JSON/JSONC/TOML, normalise every client's format into McpServer objects
rules/         one module per area; each check is  ScanTarget -> Iterable[Finding]
  catalog.py   every Rule (id, default severity, summary, remediation)
  __init__.py  CHECKS registry
scanner.py     runs discovery -> parsing -> all checks, filters and sorts
report.py      text / JSON / SARIF output
cli.py         argument parsing, exit codes
```

## Adding a rule

1. **Research the attack.** Link a writeup, CVE, or doc in your PR. Every rule should map to a real risk.
2. Add a `Rule` to `rules/catalog.py` with the **next unused ID** (never reuse IDs), then add it to `ALL_RULES`.
3. Write the check in the right module (or a new one):
   ```python
   def check_my_thing(target: ScanTarget) -> Iterator[Finding]:
       if target.kind != FileKind.CONFIG:
           return
       for s in target.servers:
           if ...:
               yield make(MY_RULE, target, f"Server '{s.name}' does X", line=target.server_line(s.name), server=s.name)
   ```
4. Register it in `rules/__init__.py` → `CHECKS`.
5. Add tests in `tests/test_rules.py`: **at least one true positive and one near-miss that must not fire**. False positives drive users away faster than missed findings.
6. Document it in the README rules table.

## Ground rules

- Never print a full secret. Use `redact()`.
- Never put real or realistic-looking credentials in the repo. Build them at runtime in tests (see `fake()` in `tests/conftest.py`).
- Keep zero runtime dependencies.

## Dev setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```
