"""What a bundle *says about itself* — the other half of every mismatch rule.

`curl` appears in about a third of installed bundles; on its own it means nothing. What
means something is `curl` inside a bundle whose description says it works offline. So
the scanner needs a cheap, conservative model of the claims a bundle makes.

Conservative in a specific direction:

* ``declares_network`` is **generous**. Any hint of network intent (api, http, fetch,
  download, url, cloud, search, a WebFetch tool grant, a Bash(curl) grant) counts. A
  generous network claim *suppresses* mismatch findings, so being generous here trades
  recall for the specificity the README demands.
* ``claims_offline`` is **narrow**: it needs an explicit offline/local-only/no-network
  statement, and it is cancelled by any network declaration, because a description that
  says both is ambiguous rather than deceptive.
* ``purpose_category`` is advisory. It sharpens the wording of *why* a finding matters
  and gates only the weakest branch of NETWORK_IN_OFFLINE_CLAIM. It never gates a
  CRITICAL rule.

Claims come from frontmatter (name/description/allowed-tools) and from the first part of
the document body, which is where a SKILL.md states its purpose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = ["Claims", "derive", "derive_from_text"]

# How much of the body counts as "the bundle describing itself".
_BODY_CLAIM_CHARS = 1200

_OFFLINE_RE = re.compile(
    r"(?:\boffline\b|\bno network\b|\bwithout network\b|\bno internet\b|"
    r"\bwithout internet\b|\bwithout an internet connection\b|\bno external calls?\b|"
    r"\bno external requests?\b|\blocal[- ]only\b|\bruns? locally\b|"
    r"\bentirely local\b|\bfully local\b|\bpurely local\b|\bnever (?:sends?|uploads?)\b|"
    r"\bno data (?:leaves|is sent)\b|\bdoes not (?:use|require|need) (?:the )?(?:network|internet)\b)",
    re.I,
)

_NETWORK_RE = re.compile(
    r"(?:\bapi\b|\bapis\b|\bhttps?\b|\bhttp\b|\bfetch(?:es|ing)?\b|\bdownloads?\b|"
    r"\bdownloading\b|\bupload(?:s|ing)?\b|\bwebhooks?\b|\brequests?\b|\burls?\b|"
    r"\bendpoints?\b|\bcloud\b|\bremote\b|\bonline\b|\bscrap(?:e|es|ing)\b|"
    r"\bweb search\b|\bsearch(?:es)? the web\b|\bnetwork\b|\binternet\b|\bserver\b|"
    r"\bpublish(?:es|ing)?\b|\bdeploys?\b|\bsync(?:s|ing)?\b|\bcrawl(?:s|ing)?\b|"
    r"\brest\b|\bgraphql\b|\bs3\b|\bslack\b|\bgithub\b|\bnpm\b|\bpypi\b|\bregistry\b)",
    re.I,
)

_NETWORK_TOOL_RE = re.compile(
    r"(?:WebFetch|WebSearch|Bash\((?:curl|wget|npm|pip|git|http)|mcp__fetch|fetch)",
    re.I,
)

_READ_ONLY_RE = re.compile(
    r"(?:\bread[- ]only\b|\bdoes not modify\b|\bnever modifies\b|\bno changes to your "
    r"system\b|\bmakes no changes\b|\bnon[- ]destructive\b|\bwithout modifying\b)",
    re.I,
)

_CREDENTIAL_PURPOSE_RE = re.compile(
    r"(?:\bssh\b|\bgpg\b|\bgnupg\b|\bkeychain\b|\bcredentials?\b|\bsecrets?\b|"
    r"\bpasswords?\b|\bvault\b|\bkeypair\b|\bssh keys?\b|\bapi keys?\b|\btokens?\b|"
    r"\bdotenv\b|\b\.env\b|\benv(?:ironment)? (?:file|var)|\baws profile\b|"
    r"\bcredential (?:manager|helper|rotation)\b|\bkey management\b|\b1password\b|"
    r"\bauthentication\b|\bauth\b)",
    re.I,
)

_LOCAL_PURPOSE_RE = re.compile(
    r"(?:\bformat(?:s|ting|ter)?\b|\blint(?:s|ing|er)?\b|\bmarkdown\b|\bdocs?\b|"
    r"\bdocumentation\b|\bwrit(?:e|es|ing)\b|\bstyle guide\b|\bprose\b|\bsummar(?:y|ise|ize)\w*\b|"
    r"\bexplain(?:s)?\b|\breview(?:s|ing)?\b|\brefactor\w*\b|\brename\w*\b|\bconvert(?:s|ing)?\b|"
    r"\btemplate\w*\b|\bboilerplate\b|\bcheatsheet\b|\bnotes?\b|\bplan(?:ning|s)?\b|"
    r"\bdiagram\w*\b|\bspell\w*\b|\bgrammar\b|\bindent\w*\b|\bpretty[- ]print\w*\b)",
    re.I,
)

_NETWORKY_PURPOSE_RE = re.compile(
    r"(?:\bdeploy\w*\b|\binstall\w*\b|\bpublish\w*\b|\bfetch\w*\b|\bdownload\w*\b|"
    r"\bapi\b|\bclient\b|\bsync\w*\b|\bupload\w*\b|\bscrap\w*\b|\bcrawl\w*\b|"
    r"\bwebhook\b|\bnotif(?:y|ication)\w*\b|\bmonitor\w*\b|\btelemetry\b)",
    re.I,
)

_TOOL_KEYS = ("allowed-tools", "allowed_tools", "tools", "allowedTools", "disallowedTools")
_DESCRIPTION_KEYS = (
    "description",
    "summary",
    "instructions",
    "about",
    "purpose",
    "name",
    "title",
    "argument-hint",
)


@dataclass
class Claims:
    """A bundle's self-description, reduced to the few bits the rules need."""

    allowed_tools: List[str] = field(default_factory=list)
    declares_tool_restrictions: bool = False
    claims_offline: bool = False
    declares_network: bool = False
    claims_read_only: bool = False
    credential_purpose: bool = False
    purpose_category: str = "unknown"
    description: str = ""
    #: The exact phrase that produced claims_offline, for use as finding evidence.
    offline_phrase: str = ""
    #: The exact phrase that produced declares_network (empty when none).
    network_phrase: str = ""

    @property
    def local_purpose(self) -> bool:
        return self.purpose_category == "local"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed_tools": list(self.allowed_tools),
            "declares_tool_restrictions": self.declares_tool_restrictions,
            "claims_offline": self.claims_offline,
            "declares_network": self.declares_network,
            "claims_read_only": self.claims_read_only,
            "credential_purpose": self.credential_purpose,
            "purpose_category": self.purpose_category,
            "offline_phrase": self.offline_phrase,
        }


def _first_match(pattern: "re.Pattern[str]", text: str) -> str:
    match = pattern.search(text)
    return match.group(0) if match else ""


def _mask_offline_phrases(text: str) -> str:
    """Blank out offline claims before looking for network intent.

    Without this, "works offline, no network required" reads as a network declaration
    (it contains the word "network") and cancels its own offline claim — the exact
    mismatch NETWORK_IN_OFFLINE_CLAIM exists to catch would silence itself.
    """
    return _OFFLINE_RE.sub(" ", text)


def derive_from_text(
    description: str,
    *,
    allowed_tools: Optional[Iterable[str]] = None,
    extra_text: str = "",
) -> Claims:
    """Derive claims from a description string plus optional tool grants."""
    tools = [str(t).strip() for t in (allowed_tools or []) if str(t).strip()]
    tools_text = " ".join(tools)
    haystack = "%s\n%s" % (description, extra_text)

    masked = _mask_offline_phrases(haystack)
    network_phrase = _first_match(_NETWORK_RE, masked)
    if not network_phrase and tools_text:
        network_phrase = _first_match(_NETWORK_TOOL_RE, tools_text)
    declares_network = bool(network_phrase)

    offline_phrase = _first_match(_OFFLINE_RE, haystack)
    claims_offline = bool(offline_phrase) and not declares_network

    local_hit = bool(_LOCAL_PURPOSE_RE.search(haystack))
    networky_hit = bool(_NETWORKY_PURPOSE_RE.search(haystack))
    if networky_hit and not local_hit:
        purpose = "network"
    elif local_hit and not networky_hit:
        purpose = "local"
    elif local_hit and networky_hit:
        purpose = "mixed"
    else:
        purpose = "unknown"

    return Claims(
        allowed_tools=tools,
        declares_tool_restrictions=bool(tools),
        claims_offline=claims_offline,
        declares_network=declares_network,
        claims_read_only=bool(_READ_ONLY_RE.search(haystack)),
        credential_purpose=bool(_CREDENTIAL_PURPOSE_RE.search(haystack)),
        purpose_category=purpose,
        description=description.strip(),
        offline_phrase=offline_phrase,
        network_phrase=network_phrase,
    )


def _collect_metadata(target: Any) -> Tuple[str, List[str], str]:
    """Pull description text, tool grants and body-prefix text out of a target."""
    from malskill import frontmatter as fm  # local import: keeps module import-cheap

    descriptions: List[str] = []
    tools: List[str] = []
    body_text: List[str] = []

    meta = getattr(target, "meta", {}) or {}

    # 1. Structured metadata recorded at discovery time (MCP servers, hooks, plugins).
    for key in _DESCRIPTION_KEYS:
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            descriptions.append(value.strip())
    for key in _TOOL_KEYS:
        value = meta.get(key)
        if isinstance(value, str):
            tools.extend(part.strip() for part in re.split(r"[,\s]+", value) if part.strip())
        elif isinstance(value, (list, tuple)):
            tools.extend(str(item).strip() for item in value if str(item).strip())

    # 2. Frontmatter of the bundle's own metadata files.
    for record in getattr(target, "files", []) or []:
        rel = (record.rel or "").replace("\\", "/")
        base = rel.rsplit("/", 1)[-1].lower()
        if record.reason and not record.has_content:
            continue
        is_metadata_file = base in ("skill.md", "agent.md", "command.md") or (
            base.endswith(".md") and "/" not in rel
        )
        if not is_metadata_file:
            continue
        parsed = fm.parse(record.text)
        if parsed.present and parsed.ok:
            for key in _DESCRIPTION_KEYS:
                value = parsed.get(key)
                if isinstance(value, str) and value.strip():
                    descriptions.append(value.strip())
                elif isinstance(value, list):
                    descriptions.append(", ".join(str(v) for v in value))
            for key in _TOOL_KEYS:
                tools.extend(parsed.get_list(key))
        body = parsed.body if parsed.present else record.text
        body_text.append(body[:_BODY_CLAIM_CHARS])

    description = "\n".join(dict.fromkeys(d for d in descriptions if d))
    return description, tools, "\n".join(body_text)


def derive(target: Any) -> Claims:
    """Derive :class:`Claims` for a loaded target (bundle, hook or MCP server)."""
    description, tools, body = _collect_metadata(target)
    if not description and not body:
        # Fall back to the target's own name: "pdf-formatter" is still a claim.
        description = str(getattr(target, "name", "")).replace("-", " ").replace("_", " ")
    return derive_from_text(description, allowed_tools=tools, extra_text=body)
