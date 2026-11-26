"""Rule registry. To add a rule: define it in catalog.py, write a check, add it to CHECKS."""

from typing import Callable, Iterable, List

from ..models import Finding, ScanTarget
from . import access, approvals, content, secrets, supply_chain
from .catalog import ALL_RULES, RULES_BY_ID

Check = Callable[[ScanTarget], Iterable[Finding]]

CHECKS: List[Check] = [
    secrets.check,
    supply_chain.check_unpinned,
    supply_chain.check_remote_code,
    access.check_filesystem,
    access.check_transport,
    supply_chain.check_containers,
    approvals.check_auto_approve,
    approvals.check_permissions,
    content.check_hidden_unicode,
    content.check_injection,
]

__all__ = ["ALL_RULES", "RULES_BY_ID", "CHECKS", "Check"]
