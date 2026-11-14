"""LLM backend abstraction.

- ``TransformersBackend`` loads the configured base model (+ optional LoRA
  adapter). torch/transformers/peft are imported lazily so the CLI and tests
  work without the heavy ML dependencies.
- ``MockBackend`` is deterministic and offline: it refuses out-of-scope
  prompts with a structured refusal and answers analysis prompts with canned,
  schema-valid findings. Used when ``AEGIS_BACKEND=mock`` is set or when
  transformers is not installed.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from . import load_yaml, project_root
from .policy import check_scope
from .schemas import Refusal

ML_MISSING_MESSAGE = (
    "The transformers/torch ML stack is not installed. Install the ML extras "
    "with: pip install -e '.[ml]' (or set AEGIS_BACKEND=mock for the "
    "deterministic offline backend)."
)

# Triggers that route a prompt to the canned red-team payload.
_REDTEAM_RE = re.compile(
    r"mode:\s*redteam|\bT\d{4}(\.\d{3})?\b|\bctf\b|\bemulat(e|ion|ing)\b|red[- ]team",
    flags=re.IGNORECASE,
)
_PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)


def _t1059_plan() -> dict[str, Any]:
    return {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "objective": (
            "Emulate adversary command execution through scripting interpreters "
            "in the authorized lab to validate and tune detections."
        ),
        "lab_preconditions": (
            "Authorized isolated lab range; instrumented victim VM with Sysmon/"
            "auditd forwarding to the SIEM; pre-engagement snapshot for rollback."
        ),
        "procedure": [
            "Confirm written authorization and lab scope for the target range.",
            "On the isolated victim VM, run benign commands (whoami, hostname, ipconfig/ifconfig) via cmd, PowerShell, and bash to emulate T1059 execution.",
            "Record process-creation telemetry, command lines, and parent/child relationships.",
            "Map observed events to detection logic, tune rules, and re-run to confirm they fire.",
        ],
        "detection_opportunities": [
            "Sysmon Event ID 1 (process creation) with suspicious or encoded command lines",
            "PowerShell Script Block Logging (Event ID 4104) and Module Logging (4103)",
            "Sigma rule on anomalous parent/child process relationships (e.g. office apps spawning shells)",
        ],
        "cleanup": [
            "Terminate any emulated processes and shells.",
            "Revert the victim VM to its pre-engagement snapshot.",
            "Archive lab telemetry to the evidence store and reset credentials used in the lab.",
        ],
        "safety_notes": (
            "Benign commands only; nothing leaves the isolated lab range; the "
            "purpose is detection validation, not capability development."
        ),
    }


def _t1046_plan(target_range: str) -> dict[str, Any]:
    return {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "objective": (
            f"Enumerate hosts and services in the authorized lab range "
            f"{target_range} to plan the exercise and validate network detections."
        ),
        "lab_preconditions": (
            "Authorized lab range in scope; scanner VM inside the lab; IDS/"
            "firewall logging enabled so scans are observable."
        ),
        "procedure": [
            f"Confirm {target_range} is inside the authorized lab scope.",
            "Run a host-discovery sweep (nmap -sn) against the lab range only.",
            "Run service/version scans (nmap -sV) against discovered lab hosts.",
            "Document the attack surface and hand results to the blue team for detection review.",
        ],
        "detection_opportunities": [
            "IDS alert on TCP SYN scans / fan-out connection attempts from a single source",
            "NetFlow or firewall logs showing one host touching many ports across the range",
            "SIEM correlation rule: connection attempts to >N distinct ports within a time window",
        ],
        "cleanup": [
            "Stop all scan processes.",
            "Remove temporary scan output from shared storage after archiving to the evidence store.",
            "Verify no lab firewall rules were changed during the exercise.",
        ],
        "safety_notes": (
            "Scan the authorized lab range only; confirm scope before every run; "
            "throttle scan rates to avoid disrupting shared lab infrastructure."
        ),
    }


def _canned_redteam_payload(prompt: str, file_path: str) -> dict[str, Any]:
    """Deterministic lab red-team output: a finding plus emulation plans."""
    plans = [_t1059_plan()]
    ip_match = _PRIVATE_IP_RE.search(prompt)
    if ip_match:
        plans.append(_t1046_plan(ip_match.group(1)))
    findings = [
        {
            "title": "Authorized lab engagement plan drafted",
            "file": file_path or "unknown",
            "lines": "1-10",
            "evidence": "Authorized lab brief supplied with defined scope, targets, and rules of engagement for the exercise.",
            "severity": "medium",
            "confidence": 0.8,
            "preconditions": "Written authorization and access to the isolated lab range.",
            "impact": "Findings apply only to the lab environment and inform defensive readiness.",
            "remediation": "Track weaknesses identified during the lab exercise through the normal remediation process.",
            "regression_test": "Re-run the emulation plan after fixes and confirm the mapped detections fire.",
            "detection_idea": "Forward all lab telemetry to the SIEM and alert on the mapped ATT&CK techniques.",
            "limitations": "Lab-only scope; results do not generalize to production without further review.",
            "safe_next_steps": "Execute the emulation plan, validate detections with the blue team, and document outcomes.",
        }
    ]
    return {"findings": findings, "emulation_plans": plans}


def _canned_findings(file_path: str) -> list[dict[str, Any]]:
    """Deterministic canned findings keyed off the analyzed file type."""
    if file_path.endswith(".c"):
        return [
            {
                "title": "Stack buffer overflow via strcpy",
                "file": file_path,
                "lines": "12-18",
                "evidence": "strcpy() copies attacker-controlled argv[1] into the fixed 64-byte stack buffer 'buf' without a length check.",
                "severity": "critical",
                "confidence": 0.95,
                "preconditions": "Attacker can supply a command-line argument longer than 63 bytes to the program.",
                "impact": "Stack corruption leading to crash or potential control-flow hijack of the local process.",
                "remediation": "Replace strcpy with a bounded copy (e.g. snprintf(buf, sizeof buf, \"%s\", argv[1])) or use dynamic sizing; also replace the snprintf call that passes user input as the format string with a constant format.",
                "regression_test": "Run the binary with a 256-byte argument under ASan and assert a clean exit with no stack-buffer-overflow report.",
                "detection_idea": "Grep/CodeQL rule flagging strcpy/strcat/sprintf calls on stack buffers; alert on crashes with PC on the stack in crash telemetry.",
                "limitations": "Static review only; no dynamic confirmation of exploitability was performed.",
                "safe_next_steps": "Apply the bounded-copy fix, add the ASan regression test, and re-run static analysis.",
            }
        ]
    if file_path.endswith((".yaml", ".yml")):
        return [
            {
                "title": "Debug mode enabled and TLS verification disabled",
                "file": file_path,
                "lines": "4-7",
                "evidence": "Config sets debug: true and tls.verify: false for the service.",
                "severity": "high",
                "confidence": 0.9,
                "preconditions": "Service is deployed with this configuration outside a local dev environment.",
                "impact": "Debug endpoints may leak internals; disabled TLS verification allows man-in-the-middle tampering of upstream connections.",
                "remediation": "Set debug: false and tls.verify: true for all non-local environments; pin CA bundles explicitly.",
                "regression_test": "Config lint test that fails CI when debug is true or tls.verify is false outside the dev profile.",
                "detection_idea": "Alert on process start with debug flags in production namespaces; detect TLS handshake failures/certificate errors in service logs.",
                "limitations": "Review covers this config file only; environment-specific overrides were not inspected.",
                "safe_next_steps": "Fix the config, add the CI lint rule, and verify the service rejects invalid certificates.",
            }
        ]
    return [
        {
            "title": "Insufficient input validation",
            "file": file_path or "unknown",
            "lines": "1-10",
            "evidence": "Externally supplied input is consumed without visible validation or bounds checks.",
            "severity": "medium",
            "confidence": 0.6,
            "preconditions": "Attacker-controlled input reaches the reviewed code path.",
            "impact": "Malformed input may cause unexpected state, crashes, or downstream security issues.",
            "remediation": "Validate and bound all external input at the trust boundary; reject unexpected values early.",
            "regression_test": "Unit tests feeding malformed/oversized inputs asserting clean rejection.",
            "detection_idea": "Log and alert on input-validation failures above a baseline rate.",
            "limitations": "Deterministic mock review; depth is limited compared to a full manual audit.",
            "safe_next_steps": "Add validation at the boundary and cover it with fuzz/unit tests.",
        }
    ]


class MockBackend:
    """Deterministic offline backend used for tests and demos."""

    name = "mock"

    def __init__(self) -> None:
        self.calls = 0

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        self.calls += 1
        # Defense in depth: the mock also enforces the scope policy, so policy
        # probes get a structured refusal even without a caller-side gate.
        # Only the user prompt is checked - the harness system prompt must not
        # be able to supply (or strip) scope markers.
        scope = check_scope(prompt)
        if not scope.allowed:
            refusal = Refusal(
                reason=scope.refusal_message or "out of scope",
                matched_patterns=scope.matched_patterns,
                safe_alternative=(
                    "Rephrase as a defensive task: code review, threat modeling, "
                    "remediation, detection engineering, or authorized-lab reporting."
                ),
            )
            return json.dumps(refusal.model_dump())
        # Data-curator pass-through: echo pre-structured records verbatim.
        match = re.search(r"RAW_RECORD:\s*(\{.*\})\s*END_RAW_RECORD", prompt, flags=re.DOTALL)
        if match:
            return match.group(1)
        file_path = self._detect_file(prompt)
        # Lab-scoped red-team prompts get the canned emulation payload.
        if _REDTEAM_RE.search(prompt) or "red team" in system_prompt.lower():
            return json.dumps(_canned_redteam_payload(prompt, file_path))
        return json.dumps(_canned_findings(file_path))

    @staticmethod
    def _detect_file(prompt: str) -> str:
        match = re.search(r"^File:\s*(\S+)", prompt, flags=re.MULTILINE)
        return match.group(1) if match else "unknown"


class TransformersBackend:
    """Local transformers backend: base model + optional LoRA adapter."""

    name = "transformers"

    def __init__(
        self,
        model_id: str,
        revision: str | None = None,
        adapter_path: Path | None = None,
        load_in_4bit: bool = False,
    ) -> None:
        try:
            import torch  # noqa: F401
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(ML_MISSING_MESSAGE) from exc

        kwargs: dict[str, Any] = {"device_map": "auto"}
        if revision:
            kwargs["revision"] = revision
        if load_in_4bit:
            from transformers import BitsAndBytesConfig

            kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True)

        self.tokenizer = AutoTokenizer.from_pretrained(model_id, revision=revision or None)
        self.model = AutoModelForCausalLM.from_pretrained(model_id, **kwargs)
        if adapter_path is not None:
            try:
                from peft import PeftModel
            except ImportError as exc:
                raise RuntimeError(ML_MISSING_MESSAGE) from exc
            self.model = PeftModel.from_pretrained(self.model, str(adapter_path))
        self.model.eval()

    @classmethod
    def from_configs(cls, adapter_path: Path | None = None) -> "TransformersBackend":
        root = project_root()
        base_cfg = load_yaml(root / "configs" / "base_model.yaml")
        # AEGIS_MODEL_ID overrides the configured base (e.g. a small instruct
        # model for local analyze smoke runs on limited VRAM).
        model_id = os.environ.get("AEGIS_MODEL_ID") or base_cfg["model_id"]
        load_in_4bit = os.environ.get("AEGIS_LOAD_IN_4BIT", "").lower() in ("1", "true")
        return cls(
            model_id=model_id,
            revision=base_cfg.get("revision") or None,
            adapter_path=adapter_path,
            load_in_4bit=load_in_4bit,
        )

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        if getattr(self.tokenizer, "chat_template", None):
            text = self.tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        else:
            # Base LMs (e.g. the tiny smoke model) have no chat template.
            text = (system_prompt + "\n\n" if system_prompt else "") + prompt + "\n"
        inputs = self.tokenizer(text, return_tensors="pt")
        # Respect absolute position-embedding limits (e.g. GPT-2's 1024):
        # prompt + new tokens must fit within the position table.
        max_positions = getattr(self.model.config, "n_positions", None) or getattr(
            self.model.config, "max_position_embeddings", None
        )
        budget = 1024
        if max_positions:
            if inputs["input_ids"].shape[1] >= max_positions:
                keep = max_positions - 1
                inputs = {k: v[:, -keep:] for k, v in inputs.items()}
            budget = max(1, min(budget, max_positions - inputs["input_ids"].shape[1]))
        inputs = inputs.to(self.model.device)
        output_ids = self.model.generate(**inputs, max_new_tokens=budget)
        new_ids = output_ids[0][inputs["input_ids"].shape[1]:]
        return self.tokenizer.decode(new_ids, skip_special_tokens=True)


def backend_for_adapter(record) -> TransformersBackend:
    """TransformersBackend for an AdapterRecord's own base model + adapter.

    Adapters trained against the configured (large) base model are loaded
    4-bit to fit workstation VRAM, matching their QLoRA training setup.
    """
    import torch

    from . import project_root as _root

    base_cfg = load_yaml(_root() / "configs" / "base_model.yaml")
    is_configured_base = record.base_model_id == base_cfg["model_id"]
    load_in_4bit = os.environ.get("AEGIS_LOAD_IN_4BIT", "").lower() in ("1", "true") or (
        is_configured_base and torch.cuda.is_available()
    )
    return TransformersBackend(
        model_id=record.base_model_id,
        revision=record.base_model_revision or None,
        adapter_path=_root() / record.path,
        load_in_4bit=load_in_4bit,
    )


def get_backend(adapter_path: Path | None = None):
    """Factory: MockBackend when AEGIS_BACKEND=mock or transformers is missing."""
    if os.environ.get("AEGIS_BACKEND", "").lower() == "mock":
        return MockBackend()
    try:
        import transformers  # noqa: F401
    except ImportError:
        return MockBackend()
    return TransformersBackend.from_configs(adapter_path=adapter_path)
