"""Every rule caniscan knows about. IDs are stable: never reuse or renumber them."""

from ..models import Rule
from ..models import Severity as S

HARDCODED_SECRET = Rule(
    "CS001", "hardcoded-secret", S.CRITICAL,
    "A credential is written in plain text inside an agent/MCP config or instruction file.",
    "Move the value to an environment variable or secret manager and reference it "
    "(e.g. \"${env:GITHUB_TOKEN}\" or \"${input:token}\" in VS Code). Rotate the exposed credential.",
)
UNPINNED_PACKAGE = Rule(
    "CS002", "unpinned-package", S.MEDIUM,
    "An MCP server is launched from a registry without a pinned version, so any launch can run new, unreviewed code.",
    "Pin an exact version (npx -y pkg@1.2.3, uvx pkg==1.2.3, image@sha256:...) and upgrade deliberately.",
)
REMOTE_CODE = Rule(
    "CS003", "remote-code-execution", S.HIGH,
    "The server command downloads a script from the internet and executes it immediately.",
    "Install a released, versioned package instead, or download, review and pin the script.",
)
BROAD_FS = Rule(
    "CS004", "broad-filesystem-access", S.HIGH,
    "A server is given the filesystem root, a whole home directory, or a credential directory.",
    "Grant only the project directories the agent actually needs.",
)
INSECURE_TRANSPORT = Rule(
    "CS005", "insecure-transport", S.MEDIUM,
    "A remote MCP endpoint is reached over unencrypted HTTP or WS.",
    "Use https:// or wss://. Plain HTTP exposes tool calls, results and tokens to anyone on the network path.",
)
DANGEROUS_CONTAINER = Rule(
    "CS006", "dangerous-container", S.HIGH,
    "A containerised server runs with options that break container isolation.",
    "Remove --privileged, host namespaces and docker.sock / host-root mounts. Mount only what is needed, read-only where possible.",
)
AUTO_APPROVE = Rule(
    "CS007", "auto-approved-tools", S.MEDIUM,
    "Tool calls run without confirmation, so a prompt injection can trigger them with no human in the loop.",
    "Limit auto-approval to read-only tools; require confirmation for anything that writes, executes or sends data.",
)
PERMISSIONS_BYPASS = Rule(
    "CS008", "permissions-bypass", S.HIGH,
    "Agent settings disable permission prompts or allow broad shell access.",
    "Remove bypass modes and replace blanket allow rules with narrow, specific commands.",
)
HIDDEN_UNICODE = Rule(
    "CS009", "hidden-unicode", S.HIGH,
    "Invisible or direction-changing Unicode can hide instructions that the model reads but a human reviewer cannot see.",
    "Delete the characters (the evidence shows where they are) and review who last changed the file.",
)
INJECTION_PHRASE = Rule(
    "CS010", "prompt-injection-phrase", S.MEDIUM,
    "An instruction file contains wording typical of prompt-injection or data-exfiltration attempts.",
    "Review the text and remove anything that overrides instructions, hides actions from the user or sends data out.",
)
FILE_PERMISSIONS = Rule(
    "CS011", "insecure-file-permissions", S.MEDIUM,
    "Other users on this machine can modify this file (or read the secrets in it).",
    "chmod 600 files that contain secrets (644 otherwise) and check the file owner.",
)

ALL_RULES = [
    HARDCODED_SECRET, UNPINNED_PACKAGE, REMOTE_CODE, BROAD_FS, INSECURE_TRANSPORT,
    DANGEROUS_CONTAINER, AUTO_APPROVE, PERMISSIONS_BYPASS, HIDDEN_UNICODE,
    INJECTION_PHRASE, FILE_PERMISSIONS,
]
RULES_BY_ID = {r.id: r for r in ALL_RULES}
