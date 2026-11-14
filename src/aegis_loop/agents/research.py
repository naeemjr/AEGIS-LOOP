"""Research agent: live, read-only, public-source enrichment.

Attaches public references to merged findings and emulation plans:

- **NVD CVE API** - findings are mapped to relevant CVEs via short keyword
  queries derived from finding titles (max ``MAX_NVD_QUERIES`` per run, with
  a courtesy delay between queries and a per-request timeout).
- **MITRE ATT&CK** - emulation-plan technique IDs are mapped to official
  technique names/URLs using the public STIX bundle, downloaded once and
  cached under ``data/cache/``; the cache is refreshed only when missing or
  older than ``ATTACK_CACHE_MAX_AGE_DAYS`` days. All lookups are local after
  caching.

Privacy: target code and file contents are NEVER sent remotely. The only
outbound data are short keyword strings derived from finding titles and
ATT&CK technique IDs (e.g. "T1059").

Offline behavior: ``--offline`` or ``AEGIS_OFFLINE=1`` disables all network
access; only an already-cached ATT&CK bundle is used (NVD is skipped). With
the MockBackend, deterministic canned references are attached instead, so
tests never touch the network. Any network failure degrades gracefully to
fewer (or no) references.
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .. import project_root
from ..schemas import EmulationPlan, Finding, Reference
from .base import AgentBase

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"
ATTACK_BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
ATTACK_TECHNIQUE_URL = "https://attack.mitre.org/techniques/"

ATTACK_CACHE_NAME = "attack-enterprise.json"
ATTACK_META_NAME = "attack-enterprise.meta.json"
ATTACK_CACHE_MAX_AGE_DAYS = 7

MAX_NVD_QUERIES = 3
NVD_RESULTS_PER_QUERY = 2
NVD_DELAY_SECONDS = 1.0
REQUEST_TIMEOUT_SECONDS = 10
USER_AGENT = "aegis-loop-research/0.1 (read-only public-source enrichment)"

_SNIPPET_LEN = 240

_STOPWORDS = {
    "a", "an", "the", "via", "in", "of", "to", "and", "or", "on", "for",
    "with", "without", "by", "is", "due", "from", "into", "when", "that",
}


def offline_requested(flag: bool = False) -> bool:
    """Offline when the flag is set or AEGIS_OFFLINE is truthy."""
    return flag or os.environ.get("AEGIS_OFFLINE", "").lower() in ("1", "true", "yes")


def keywords_from_title(title: str, max_words: int = 4) -> str:
    """Derive a short NVD keyword query from a finding title.

    e.g. "Stack buffer overflow via strcpy" -> "stack buffer overflow strcpy".
    """
    words = re.findall(r"[a-z0-9]+", title.lower())
    significant = [w for w in words if w not in _STOPWORDS]
    return " ".join(significant[:max_words])


def dedupe_references(references: list[Reference]) -> list[Reference]:
    """Drop duplicate references by (source, id), keeping the first seen."""
    seen: set[tuple[str, str]] = set()
    kept: list[Reference] = []
    for ref in references:
        key = (ref.source, ref.id)
        if key not in seen:
            seen.add(key)
            kept.append(ref)
    return kept


def _cve_severity(cve: dict) -> str | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            severity = entries[0].get("cvssData", {}).get("baseSeverity")
            if severity:
                return str(severity).lower()
    entries = metrics.get("cvssMetricV2")
    if entries:
        severity = entries[0].get("baseSeverity")
        if severity:
            return str(severity).lower()
    return None


def _attack_technique_url(technique_id: str) -> str:
    # Sub-techniques use a path segment: T1059.001 -> /techniques/T1059/001/
    return ATTACK_TECHNIQUE_URL + technique_id.replace(".", "/") + "/"


def _mock_nvd_reference() -> Reference:
    return Reference(
        source="nvd",
        id="CVE-2021-3156",
        title="Mock NVD fixture: heap-based buffer overflow in sudo (Baron Samedit)",
        url=NVD_DETAIL_URL + "CVE-2021-3156",
        severity="high",
        snippet=(
            "Deterministic canned reference attached when AEGIS_BACKEND=mock; "
            "no network traffic is performed."
        ),
    )


def _mock_attack_reference(plan: EmulationPlan) -> Reference:
    return Reference(
        source="attack",
        id=plan.technique_id,
        title=f"{plan.name} (mock ATT&CK fixture)",
        url=_attack_technique_url(plan.technique_id),
        severity=None,
        snippet=(
            "Deterministic canned reference attached when AEGIS_BACKEND=mock; "
            "no network traffic is performed."
        ),
    )


class ResearchAgent(AgentBase):
    """Enriches findings/plans with live public references (see module docstring)."""

    def __init__(
        self,
        backend,
        prompts_dir=None,
        cache_dir: Path | None = None,
        offline: bool = False,
        nvd_delay: float = NVD_DELAY_SECONDS,
    ) -> None:
        super().__init__("research", backend, prompts_dir)
        self.cache_dir = Path(cache_dir) if cache_dir else project_root() / "data" / "cache"
        self.offline = offline_requested(offline)
        self.nvd_delay = nvd_delay

    @property
    def _is_mock(self) -> bool:
        return getattr(self.backend, "name", "") == "mock"

    # ------------------------------------------------------------------ API

    def enrich(
        self, findings: list[Finding], plans: list[EmulationPlan]
    ) -> list[str]:
        """Attach references in place; returns human-readable notes/warnings."""
        notes: list[str] = []
        if self._is_mock:
            for finding in findings:
                finding.references = dedupe_references(
                    [*finding.references, _mock_nvd_reference()]
                )
            for plan in plans:
                plan.references = dedupe_references(
                    [*plan.references, _mock_attack_reference(plan)]
                )
            notes.append("mock backend: attached canned references (no network)")
            return notes

        if not self.offline:
            notes.extend(self._attach_nvd_references(findings))
        else:
            notes.append("offline mode: NVD lookups skipped")

        index, index_notes = self._load_attack_index()
        notes.extend(index_notes)
        for plan in plans:
            entry = index.get(plan.technique_id)
            if entry is None:
                notes.append(f"no ATT&CK cache entry for {plan.technique_id}")
                continue
            ref = Reference(
                source="attack",
                id=plan.technique_id,
                title=entry["name"],
                url=entry["url"],
                severity=None,
                snippet=entry.get("description", "")[:_SNIPPET_LEN],
            )
            plan.references = dedupe_references([*plan.references, ref])
        return notes

    # ------------------------------------------------------------------ NVD

    def _attach_nvd_references(self, findings: list[Finding]) -> list[str]:
        notes: list[str] = []
        queries = 0
        seen_keywords: set[str] = set()
        for finding in findings:
            if queries >= MAX_NVD_QUERIES:
                break
            keywords = keywords_from_title(finding.title)
            if not keywords or keywords in seen_keywords:
                continue
            seen_keywords.add(keywords)
            if queries:
                time.sleep(self.nvd_delay)  # rate-limit courtesy
            queries += 1
            try:
                refs = self._nvd_query(keywords)
            except Exception as exc:  # noqa: BLE001 - graceful network degradation
                notes.append(f"NVD query {keywords!r} failed: {exc}")
                continue
            finding.references = dedupe_references([*finding.references, *refs])
        if queries == 0 and findings:
            notes.append("no NVD queries issued (no usable finding keywords)")
        return notes

    def _nvd_query(self, keywords: str) -> list[Reference]:
        params = urlencode(
            {"keywordSearch": keywords, "resultsPerPage": NVD_RESULTS_PER_QUERY}
        )
        request = Request(
            f"{NVD_API_URL}?{params}",
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
        with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
        references: list[Reference] = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            description = next(
                (
                    d.get("value", "")
                    for d in cve.get("descriptions", [])
                    if d.get("lang") == "en"
                ),
                "",
            )
            references.append(
                Reference(
                    source="nvd",
                    id=cve_id,
                    title=cve_id,
                    url=NVD_DETAIL_URL + cve_id,
                    severity=_cve_severity(cve),
                    snippet=description[:_SNIPPET_LEN],
                )
            )
        return references

    # -------------------------------------------------------------- ATT&CK

    @property
    def _attack_cache_path(self) -> Path:
        return self.cache_dir / ATTACK_CACHE_NAME

    @property
    def _attack_meta_path(self) -> Path:
        return self.cache_dir / ATTACK_META_NAME

    def _attack_cache_fresh(self) -> bool:
        if not self._attack_cache_path.exists() or not self._attack_meta_path.exists():
            return False
        try:
            meta = json.loads(self._attack_meta_path.read_text(encoding="utf-8"))
            downloaded_at = datetime.fromisoformat(meta["downloaded_at"])
        except (ValueError, KeyError, json.JSONDecodeError):
            return False
        age = datetime.now(timezone.utc) - downloaded_at
        return age < timedelta(days=ATTACK_CACHE_MAX_AGE_DAYS)

    def _download_attack_bundle(self) -> str | None:
        """Fetch the STIX bundle into the cache; returns an error note on failure."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            request = Request(ATTACK_BUNDLE_URL, headers={"User-Agent": USER_AGENT})
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                payload = response.read()
            tmp_path = self._attack_cache_path.with_suffix(".json.tmp")
            tmp_path.write_bytes(payload)
            tmp_path.replace(self._attack_cache_path)
            meta = {
                "source": ATTACK_BUNDLE_URL,
                "downloaded_at": datetime.now(timezone.utc).isoformat(),
                "bytes": len(payload),
            }
            self._attack_meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        except Exception as exc:  # noqa: BLE001 - graceful network degradation
            return f"ATT&CK bundle download failed: {exc}"
        return None

    def _load_attack_index(self) -> tuple[dict[str, dict], list[str]]:
        """technique id -> {name, url, description}; local-only after caching."""
        notes: list[str] = []
        if self.offline:
            if self._attack_cache_path.exists():
                notes.append("offline mode: using existing ATT&CK cache")
            else:
                notes.append("offline mode: no ATT&CK cache available, lookups skipped")
                return {}, notes
        elif not self._attack_cache_fresh():
            error = self._download_attack_bundle()
            if error:
                notes.append(error)
                if not self._attack_cache_path.exists():
                    return {}, notes
                notes.append("falling back to stale ATT&CK cache")
        if not self._attack_cache_path.exists():
            return {}, notes
        try:
            data = json.loads(self._attack_cache_path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as exc:
            notes.append(f"ATT&CK cache unreadable: {exc}")
            return {}, notes
        index: dict[str, dict] = {}
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            technique_id = None
            url = None
            for ext in obj.get("external_references", []):
                if ext.get("source_name") == "mitre-attack" and ext.get("external_id"):
                    technique_id = ext["external_id"]
                    url = ext.get("url") or _attack_technique_url(technique_id)
                    break
            if technique_id:
                index[technique_id] = {
                    "name": obj.get("name", technique_id),
                    "url": url or _attack_technique_url(technique_id),
                    "description": obj.get("description", ""),
                }
        return index, notes
