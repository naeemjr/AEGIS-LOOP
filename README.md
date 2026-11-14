# AEGIS-LOOP

Versioned LoRA/QLoRA fine-tuning and multi-agent analysis pipeline for
**defensive** security research: code review, threat modeling, remediation,
detection engineering, and authorized-lab reporting.

## Scope and ethics

AEGIS-LOOP is built for defensive security work, plus offensive security
**only inside authorized lab environments** (HackTheBox / OWASP Juice Shop /
Atomic Red Team style training ranges):

- **In scope (defensive):** code review, threat modeling, remediation,
  detection engineering, authorized-lab reporting.
- **In scope (lab offensive, requires a scope marker):** lab recon and
  enumeration planning, CTF challenge walkthroughs, MITRE ATT&CK technique
  emulation paired with detection opportunities (purple-team style), and lab
  exploit walkthroughs against vulnerable-by-design targets (Juice Shop,
  DVWA, Metasploitable, ...). A lab scope marker is required: the `--lab`
  flag, the word "lab"/"CTF" in the request, a private RFC1918/loopback IP
  range, a named vulnerable-by-design training app, or an ATT&CK technique ID
  (T####). Ambiguous dual-use requests without a marker are refused with
  instructions on how to scope them.
- **Always refused, even with `--lab`:** targeting real third-party systems
  or people, authoring deployable malware/ransomware/phishing kits,
  credential theft against real people, persistence/evasion on real
  production systems, doxxing, weaponized zero-days.

The policy gate lives in `configs/policy.yaml` + `src/aegis_loop/policy.py`
(`refuse_patterns` vs `restricted_patterns` vs `lab_scope_markers`) and runs
before any model call. The bundled examples (`examples/`) are intentionally
insecure *review fixtures* and an authorized-lab CTF brief, not operational
material.

## Quickstart

### One-command mode

`aegis-loop go` runs the whole pipeline in one shot — scope-policy gate,
multi-agent analysis (auto mode by default), Markdown report — and prints a
terminal summary (findings by severity, top finding titles, report path).
Outputs land in `runs/go-<timestamp>/` (override with `--out-dir`).

```bash
# analyze a file
AEGIS_BACKEND=mock .venv/bin/aegis-loop go --target examples/vuln_app.c

# or analyze a request brief, with lab scope and live research enrichment
.venv/bin/aegis-loop go --request "threat emulation plan for a lab CTF range" --lab --research
```

`go` accepts `--target <path>` **or** `--request <text>`, plus `--mode`,
`--lab`, `--research`, and `--offline`.

For convenience, `bin/aegis` runs the CLI from any directory (it resolves the
repo root from its own path and pins `AEGIS_LOOP_ROOT`). A symlink is
installed at `~/.local/bin/aegis`; if `~/.local/bin` is on your `PATH`, plain
`aegis go ...` works from anywhere:

```bash
aegis go --target ~/some/file.c --research
```

### Mock path (no GPU, no ML deps)

```bash
python3 -m venv .venv
.venv/bin/pip install -e .[dev]

# run the tests (no GPU, no ML deps needed)
.venv/bin/python -m pytest tests/ -q

# analyze a fixture with the deterministic mock backend
AEGIS_BACKEND=mock .venv/bin/aegis-loop analyze --target examples/vuln_app.c --out runs/findings.json
.venv/bin/aegis-loop report --findings runs/findings.json --out runs/report.md
```

### Real path (GPU)

Verified on: RTX 4070 12GB, Python 3.14, torch 2.13.0+cu130, transformers
5.15.0, peft 0.20.0, trl 1.10.0, bitsandbytes 0.50.1.

```bash
.venv/bin/pip install -e .[ml]        # torch, transformers, peft, trl, datasets, accelerate, bitsandbytes

# seed a 24-example approved dataset from the bundled fixtures and curate it
AEGIS_LOOP_ROOT=$PWD .venv/bin/python scripts/seed_dataset.py

# smoke-train a LoRA adapter on the tiny model (seconds on GPU)
.venv/bin/aegis-loop train --smoke

# evaluate the adapter on the fixed benchmark + policy probes
.venv/bin/aegis-loop evaluate --adapter-version 1

# real analyze with a small instruct model (downloaded from HF on first use)
AEGIS_MODEL_ID=Qwen/Qwen2.5-1.5B-Instruct .venv/bin/aegis-loop analyze \
    --target examples/vuln_app.c --out runs/findings-real.json

# real QLoRA of the 7B base (4-bit nf4; fits 12GB VRAM at seq len 1024):
.venv/bin/aegis-loop train --max-steps 5 --max-length 1024
```

Notes on the real path:

- `AEGIS_MODEL_ID` overrides the base model for analyze/evaluate;
  `AEGIS_LOAD_IN_4BIT=1` loads it 4-bit quantized.
- A tiny-model adapter is expected to score ~0 on the benchmark; the
  promotion gate (composite must beat the incumbent AND zero critical policy
  failures) will correctly refuse to promote it. That is the gate working.
- For a full 7B run on bigger hardware, the defaults in `configs/lora.yaml`
  (r=16, alpha=32, nf4 double-quant, seq len 4096, lr 2e-4 cosine, 3 epochs,
  bf16, batch 1 x grad accum 8) are sized for a 24GB+ card; on 12GB keep
  `--max-length 1024` (or 512) and batch 1.

## Pipeline

- `aegis-loop ingest --source <path> --approved-by <name>` — copy approved
  files into `data/raw/`, hash-recorded in `data/registry.json`.
- `aegis-loop curate` — structure raw records into validated `TrainingExample`
  JSONL in `data/curated/`; only `human_review.status == "approved"` examples
  are emitted; each dataset gets a content-addressed version (`ds-<hash>`).
- `aegis-loop train` — QLoRA SFT on the latest curated dataset. Requires the
  heavy ML extras (`pip install -e .[ml]`); imports them lazily and exits with
  a clear message when they are absent. Saves adapters to `adapters/v<N>/`
  and a run manifest to `runs/`.
- `aegis-loop evaluate` — score an adapter (or the base model) against the
  fixed benchmark plus policy probes; promote only when the composite score
  beats the incumbent **and** `critical_policy_failures == 0`.
- `aegis-loop analyze` / `aegis-loop report` — multi-agent defensive analysis
  (code research + threat research, merged and deduplicated) and a Markdown
  findings report.
- `aegis-loop go` — one-command mode: policy gate, analyze, and report in a
  single run with a concise terminal summary (see Quickstart).

## Research agent (live public-source enrichment)

Pass `--research` to `analyze`/`go` (or set `research: true` in
`configs/base_model.yaml` — the single config location) and the research
agent (`src/aegis_loop/agents/research.py`, prompt in
`configs/prompts/research.md`) runs **after** merge/dedupe and attaches
structured `Reference` records to findings and emulation plans:

- **NVD CVE API** — findings are mapped to relevant CVEs via short keyword
  queries derived from finding titles (e.g. "strcpy buffer overflow"). At
  most 3 queries per run, a courtesy delay between queries, a 10s timeout,
  and graceful skip on any network failure. Captures CVE id, severity,
  description snippet, and the nvd.nist.gov URL.
- **MITRE ATT&CK** — emulation-plan technique IDs are mapped to official
  names/URLs using the public enterprise-attack STIX bundle. The bundle is
  downloaded once and cached at `data/cache/attack-enterprise.json` (with
  metadata in `attack-enterprise.meta.json`); it is refreshed only when
  missing or older than 7 days. All ATT&CK lookups are local after caching.

References are deduplicated by `(source, id)` and rendered in a per-finding /
per-plan **References** section of the Markdown report. With
`AEGIS_BACKEND=mock`, deterministic canned references (one NVD CVE fixture,
one ATT&CK T1059 entry) are attached instead, so tests never touch the
network.

**Privacy:** the research agent never sends target code or file contents
anywhere. The only outbound data are short keyword strings derived from
finding titles and ATT&CK technique IDs (e.g. "T1059"), sent as read-only
GET requests to the two public sources above. No API keys.

**Offline mode:** `--offline` or `AEGIS_OFFLINE=1` disables all research-agent
network access. ATT&CK lookups still work from an existing local cache; NVD
queries are skipped.

## Layout

See `src/aegis_loop/` for the pipeline modules and `configs/` for model,
LoRA, eval, policy, and agent-prompt configuration. Adapter versions and the
incumbent pointer live in `adapters/REGISTRY.json`; run manifests land in
`runs/` (gitignored).
