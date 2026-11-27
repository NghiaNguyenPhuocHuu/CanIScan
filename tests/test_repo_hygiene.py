"""Guards for the repository's own CI supply chain: pinned actions, no persisted credentials,
and a README Action example that copies the same pins."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.M)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
PIN = re.compile(r"^\s*-?\s*uses:\s*([\w.-]+/[\w./-]+)@(\S+)\s*#\s*(\S+)", re.M)


@pytest.mark.parametrize("rel", [".github/workflows/ci.yml", "action.yml"])
def test_actions_are_pinned_to_commit_shas(rel):
    refs = USES.findall((ROOT / rel).read_text(encoding="utf-8"))
    assert refs and [r for r in refs if not r.startswith("./") and not PINNED.match(r)] == []


@pytest.mark.parametrize("rel", [".github/workflows/ci.yml", "README.md"])
def test_checkout_does_not_persist_credentials(rel):
    text = (ROOT / rel).read_text(encoding="utf-8")
    n = len(re.findall(r"uses:\s*actions/checkout@", text))
    assert n and len(re.findall(r"^\s*persist-credentials:\s*false\b", text, re.M)) == n


def _pins(rel):
    """{action: (ref, version comment)} for every pinned `uses:` line in a file."""
    return {name: (ref, ver) for name, ref, ver in PIN.findall((ROOT / rel).read_text(encoding="utf-8"))}


def test_readme_action_example_matches_workflow_pins():
    # Regression: Dependabot bumped ci.yml, but the copy-paste example in the README kept the old pin.
    readme = _pins("README.md")
    ours = {**_pins(".github/workflows/ci.yml"), **_pins("action.yml")}
    shared = readme.keys() & ours.keys()
    assert "actions/checkout" in shared
    assert {k: readme[k] for k in shared} == {k: ours[k] for k in shared}, "update the README Action example"
    assert [n for n, (ref, _) in readme.items()
            if n != "NghiaNguyenPhuocHuu/CanIScan" and not re.fullmatch(r"[0-9a-f]{40}", ref)] == []
