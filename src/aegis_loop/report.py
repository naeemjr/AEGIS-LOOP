"""Render a findings JSON payload into a Markdown report via Jinja2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Template

REPORT_TEMPLATE = """\
# AEGIS-LOOP Findings Report

- **Target:** {{ target }}
- **Status:** {{ status }}
- **Mode:** {{ mode | default("auto") }}
- **Lab scope asserted:** {{ lab | default(false) }}
- **Generated:** {{ created_at }}
- **Findings:** {{ findings | length }}
- **Emulation plans:** {{ emulation_plans | default([]) | length }}

{% if status == "refused" %}
## Refusal

The request was refused by the AEGIS-LOOP scope policy.

- **Reason:** {{ refusal.reason }}
- **Matched policy rules:** {{ refusal.matched_patterns | join(", ") }}
- **Safe alternative:** {{ refusal.safe_alternative }}
{% endif %}
{% for f in findings %}
## {{ loop.index }}. {{ f.title }}

- **File:** {{ f.file }}
- **Lines:** {{ f.lines }}
- **Severity:** {{ f.severity }}
- **Confidence:** {{ f.confidence }}
- **Evidence:** {{ f.evidence }}
- **Preconditions:** {{ f.preconditions }}
- **Impact:** {{ f.impact }}
- **Remediation:** {{ f.remediation }}
- **Regression Test:** {{ f.regression_test }}
- **Detection Idea:** {{ f.detection_idea }}
- **Limitations:** {{ f.limitations }}
- **Safe Next Steps:** {{ f.safe_next_steps }}
{% if f.references %}
- **References:**
{% for r in f.references %}  - [{{ r.source | upper }}] {{ r.id }} - {{ r.title }}{% if r.severity %} (severity: {{ r.severity }}){% endif %} — {{ r.url }}
{% if r.snippet %}    > {{ r.snippet }}
{% endif %}{% endfor %}
{% endif %}
{% else %}
No findings.
{% endfor %}
{% if emulation_plans %}
## Emulation Plans (authorized lab scope)
{% for p in emulation_plans %}
### {{ p.technique_id }} - {{ p.name }}

- **Objective:** {{ p.objective }}
- **Lab Preconditions:** {{ p.lab_preconditions }}
- **Procedure:**
{% for step in p.procedure %}  {{ loop.index }}. {{ step }}
{% endfor %}
- **Detection Opportunities:**
{% for d in p.detection_opportunities %}  - {{ d }}
{% endfor %}
- **Cleanup:**
{% for c in p.cleanup %}  - {{ c }}
{% endfor %}
- **Safety Notes:** {{ p.safety_notes }}
{% if p.references %}
- **References:**
{% for r in p.references %}  - [{{ r.source | upper }}] {{ r.id }} - {{ r.title }}{% if r.severity %} (severity: {{ r.severity }}){% endif %} — {{ r.url }}
{% if r.snippet %}    > {{ r.snippet }}
{% endif %}{% endfor %}
{% endif %}
{% endfor %}
{% endif %}
"""

_template = Template(REPORT_TEMPLATE)


def render_report(payload: dict[str, Any]) -> str:
    return _template.render(**payload)


def write_report(findings_path: Path, out_path: Path) -> str:
    with open(findings_path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    rendered = render_report(payload)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    return rendered
