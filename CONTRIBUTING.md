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

## Releasing

Release tags (`v*`) are **immutable**. The `protect-release-tags` ruleset blocks moving and deleting them, with no bypass, so users can trust that a tag always means the same code. A wrong tag is never fixed in place: release the next version instead. There is no floating major tag (`v0`); users pin a commit SHA.

1. Bump the version in a pull request and merge it.
2. Tag the merged commit and push the tag:
   ```bash
   git fetch origin && git merge-base --is-ancestor <sha> origin/main   # must succeed: the commit is on main
   git tag -a vX.Y.Z <sha> -m vX.Y.Z
   git push origin vX.Y.Z
   ```
3. Check that the rule is enforced: `git push origin :refs/tags/vX.Y.Z` must be **rejected** with `GH013`. If it isn't, push the tag again immediately and fix the ruleset.
4. Publish release notes that list the commit SHA to pin.
