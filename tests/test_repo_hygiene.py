"""Guards for the repository's own CI supply chain: pinned actions, no persisted credentials."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.M)
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


@pytest.mark.parametrize("rel", [".github/workflows/ci.yml", "action.yml"])
def test_actions_are_pinned_to_commit_shas(rel):
    refs = USES.findall((ROOT / rel).read_text(encoding="utf-8"))
    assert refs and [r for r in refs if not r.startswith("./") and not PINNED.match(r)] == []


def test_checkout_does_not_persist_credentials():
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    n = len(re.findall(r"uses:\s*actions/checkout@", text))
    assert n and text.count("persist-credentials: false") == n
