#!/usr/bin/env python
"""Seed a real curated training dataset from the bundled fixtures.

Builds ~24 analyst-quality, human-approved TrainingExamples about reviewing
the intentionally vulnerable fixtures (examples/vuln_app.c,
examples/app_config.yaml) and two lab-scoped ATT&CK emulation plans
(T1059/T1046), then runs the curate pipeline (MockBackend pass-through) so the
dataset is validated and versioned in the registry.

Content policy: all examples are defensive reviews of vulnerable CODE or
authorized-lab emulation plans with detection opportunities. No malware or
operational attack payloads are included.

Usage:
    AEGIS_LOOP_ROOT=. .venv/bin/python scripts/seed_dataset.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aegis_loop.backend import MockBackend
from aegis_loop.curate import curate
from aegis_loop.schemas import TrainingExample

REVIEW = {"reviewer": "n.roussas", "status": "approved", "date": "2026-08-17"}

VULN_APP = Path("examples/vuln_app.c").read_text(encoding="utf-8")
APP_CONFIG = Path("examples/app_config.yaml").read_text(encoding="utf-8")
CTF_BRIEF = Path("examples/ctf_brief.md").read_text(encoding="utf-8")


def finding(**kw) -> dict:
    base = {
        "title": "",
        "file": "examples/vuln_app.c",
        "lines": "1-1",
        "evidence": "",
        "severity": "medium",
        "confidence": 0.9,
        "preconditions": "",
        "impact": "",
        "remediation": "",
        "regression_test": "",
        "detection_idea": "",
        "limitations": "",
        "safe_next_steps": "",
    }
    base.update(kw)
    return base


F_STRCPY = finding(
    title="Stack buffer overflow via unbounded strcpy",
    lines="24-25",
    evidence="strcpy(buf, argv[1]) copies an attacker-controlled argument into the 64-byte stack buffer 'buf' with no length check.",
    severity="critical",
    confidence=0.97,
    preconditions="Attacker can invoke the program with an argument longer than 63 bytes.",
    impact="Stack corruption: crash at minimum; on builds without stack canaries/NX, possible control-flow hijack of the local process.",
    remediation="Replace strcpy with a bounded copy: snprintf(buf, sizeof buf, \"%s\", argv[1]); or validate strlen(argv[1]) < sizeof buf before copying. Compile with -fstack-protector-strong -D_FORTIFY_SOURCE=2.",
    regression_test="Build with ASan (-fsanitize=address) and run with a 256-byte argument; assert clean exit with no stack-buffer-overflow report in CI.",
    detection_idea="Static rule (CodeQL/Semgrep) flagging strcpy/strcat/sprintf into fixed-size stack buffers; alert on SIGSEGV crashes with instruction pointer outside mapped executable pages.",
    limitations="Static review only; exploitability on the target build was not dynamically confirmed.",
    safe_next_steps="Apply the bounded-copy fix, enable the ASan regression test, and sweep the codebase for other unbounded string copies.",
)

F_FMT = finding(
    title="Format string misuse in snprintf call",
    lines="27-28",
    evidence="snprintf(msg, sizeof(msg), argv[1]) passes user-controlled input as the format string; '%' sequences in the argument are interpreted as format directives.",
    severity="high",
    confidence=0.93,
    preconditions="Attacker controls argv[1] and supplies format specifiers such as %x or %n.",
    impact="Memory disclosure via %x/%s (stack contents leaked to output); with %n on affected libc configurations, memory writes are possible.",
    remediation="Use a constant format string: snprintf(msg, sizeof msg, \"%s\", argv[1]). Enable -Wformat -Wformat-security and treat warnings as errors.",
    regression_test="Unit test invoking the program with '%x%x%x%n' as the argument asserting the literal string is printed and the process exits normally.",
    detection_idea="Compiler warning gate (-Wformat-security) in CI; Semgrep rule for snprintf/fprintf with a non-literal format argument.",
    limitations="Reviewed call site only; other printf-family calls in the project were not audited here.",
    safe_next_steps="Fix the format string, turn on -Werror=format-security, and audit remaining printf-family calls.",
)

F_SECRET = finding(
    title="Hardcoded administrative password in source",
    lines="11-12",
    evidence="#define ADMIN_PASSWORD \"Sup3rSecret!\" embeds a credential directly in the compiled binary and source history.",
    severity="high",
    confidence=0.95,
    preconditions="Anyone with read access to the source repo or the compiled binary (strings output) can recover the password.",
    impact="Full exposure of whatever this password protects; credential reuse may extend the impact to other environments.",
    remediation="Remove the secret from source, load it from a secret store or environment at runtime, and rotate the exposed password immediately; purge it from git history.",
    regression_test="CI secret-scanning job (gitleaks/trufflehog) that fails the build when credential-like strings are committed.",
    detection_idea="Secret scanning on commits; runtime canary: alert if the literal value appears in process memory dumps or logs.",
    limitations="Only this literal was confirmed; other credentials in history were not enumerated.",
    safe_next_steps="Rotate the credential, remove it from source and history, and add pre-commit secret scanning.",
)

F_DEBUG = finding(
    title="Debug mode enabled in service configuration",
    file="examples/app_config.yaml",
    lines="4-5",
    evidence="service.debug: true enables verbose error output and debug endpoints in the demo-api configuration.",
    severity="medium",
    confidence=0.9,
    preconditions="The service is deployed with this configuration outside a local development environment.",
    impact="Stack traces, internal paths, and configuration details may leak to clients; debug endpoints may expose administrative functionality.",
    remediation="Set debug: false for all non-local environments and gate debug behind an explicit dev-only profile.",
    regression_test="Config lint in CI that fails when debug is true in any profile other than local dev.",
    detection_idea="Alert on processes starting with debug flags in production namespaces; periodic config drift scan against the hardened baseline.",
    limitations="Only this config file reviewed; environment-specific overrides were not inspected.",
    safe_next_steps="Disable debug outside dev, add the CI lint rule, and verify debug endpoints are unreachable in deployed environments.",
)

F_TLS = finding(
    title="TLS certificate verification disabled",
    file="examples/app_config.yaml",
    lines="6-8",
    evidence="service.tls.verify: false disables certificate validation for upstream TLS connections.",
    severity="high",
    confidence=0.92,
    preconditions="An attacker positioned on the network path between this service and an upstream endpoint.",
    impact="Man-in-the-middle interception or tampering of upstream API traffic, including any credentials or tokens in transit.",
    remediation="Set tls.verify: true and pin an explicit CA bundle; fail closed on certificate errors instead of disabling verification.",
    regression_test="Integration test pointing the service at a TLS endpoint with a self-signed certificate, asserting the connection is rejected.",
    detection_idea="Alert on TLS handshake failures and on processes loading configurations with verification disabled; network detection for downgraded or plaintext fallback.",
    limitations="Network position requirement limits realistic exploitability to certain deployment topologies.",
    safe_next_steps="Re-enable verification, add the negative TLS integration test, and scan all configs for verify: false.",
)

F_LOG = finding(
    title="Verbose debug logging may capture sensitive data",
    file="examples/app_config.yaml",
    lines="9-10",
    evidence="service.logging.level: debug logs request/response detail that frequently includes headers, tokens, or personal data.",
    severity="low",
    confidence=0.75,
    preconditions="Debug-level logging shipped to a deployed environment with log aggregation accessible to a broad audience.",
    impact="Sensitive data exposure via log stores; increased compliance scope (e.g. PCI/GDPR) for log infrastructure.",
    remediation="Set logging.level to info in deployed environments and add explicit redaction for authorization headers and tokens.",
    regression_test="Log-pipeline test asserting no authorization headers or token patterns appear in emitted logs at info level.",
    detection_idea="DLP-style pattern alerts on log streams (bearer tokens, cookie values); alert when log level changes outside a deployment event.",
    limitations="Actual log content was not sampled; severity assumes typical framework behavior at debug level.",
    safe_next_steps="Lower the log level, add redaction, and review who can query the log store.",
)


def plan_t1059() -> dict:
    return {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "objective": "Emulate adversary command execution through scripting interpreters in the authorized lab to validate and tune detections.",
        "lab_preconditions": "Authorized isolated lab range; instrumented victim VM with Sysmon/auditd forwarding to the SIEM; pre-engagement snapshot for rollback.",
        "procedure": [
            "Confirm written authorization and lab scope for the target range.",
            "On the isolated victim VM, run benign commands (whoami, hostname, ipconfig/ifconfig) via cmd, PowerShell, and bash to emulate interpreter-based execution.",
            "Record process-creation telemetry, command lines, and parent/child relationships.",
            "Map observed events to detection logic, tune rules, and re-run to confirm they fire.",
        ],
        "detection_opportunities": [
            "Sysmon Event ID 1 (process creation) with suspicious or encoded command lines",
            "PowerShell Script Block Logging (Event ID 4104) and Module Logging (4103)",
            "Sigma rule on anomalous parent/child process relationships (e.g. office applications spawning shells)",
        ],
        "cleanup": [
            "Terminate any emulated processes and shells.",
            "Revert the victim VM to its pre-engagement snapshot.",
            "Archive lab telemetry to the evidence store and rotate any lab credentials used.",
        ],
        "safety_notes": "Benign commands only; nothing leaves the isolated lab range; the purpose is detection validation, not capability development.",
    }


def plan_t1046() -> dict:
    return {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "objective": "Enumerate hosts and services in the authorized lab range 10.10.10.0/24 to plan the exercise and validate network detections.",
        "lab_preconditions": "Authorized lab range in scope; scanner VM inside the lab; IDS/firewall logging enabled so scans are observable.",
        "procedure": [
            "Confirm 10.10.10.0/24 is inside the authorized lab scope.",
            "Run a host-discovery sweep (nmap -sn) against the lab range only.",
            "Run service/version scans (nmap -sV) against discovered lab hosts.",
            "Document the exposed services and hand results to the blue team for detection review.",
        ],
        "detection_opportunities": [
            "IDS alert on TCP SYN scans / fan-out connection attempts from a single source",
            "NetFlow or firewall logs showing one host touching many ports across the range",
            "SIEM correlation rule: connection attempts to >20 distinct ports within one minute",
        ],
        "cleanup": [
            "Stop all scan processes.",
            "Archive scan output to the evidence store and remove temporary copies.",
            "Verify no lab firewall rules were changed during the exercise.",
        ],
        "safety_notes": "Scan the authorized lab range only; confirm scope before every run; throttle scan rates to avoid disrupting shared lab infrastructure.",
    }


def payload(findings: list[dict] | None = None, plans: list[dict] | None = None) -> str:
    return json.dumps(
        {"findings": findings or [], "emulation_plans": plans or []}, indent=2
    )


def flist(*findings: dict) -> str:
    return json.dumps(list(findings), indent=2)


def build_examples() -> list[dict]:
    examples: list[dict] = []

    def add(task_type: str, instruction: str, input_text: str, output: str, source: str) -> None:
        examples.append(
            {
                "id": f"seed-{len(examples) + 1:02d}",
                "task_type": task_type,
                "instruction": instruction,
                "input": input_text,
                "output": output,
                "source_id": source,
                "human_review": REVIEW,
            }
        )

    # --- code_review (6): one finding per example, alternating inputs -------
    review_instr = "Review the following code for security vulnerabilities and report structured findings."
    config_instr = "Review the following configuration for security issues and report structured findings."
    add("code_review", review_instr, VULN_APP, flist(F_STRCPY), "examples/vuln_app.c")
    add("code_review", review_instr, VULN_APP, flist(F_FMT), "examples/vuln_app.c")
    add("code_review", review_instr, VULN_APP, flist(F_SECRET), "examples/vuln_app.c")
    add("code_review", config_instr, APP_CONFIG, flist(F_DEBUG), "examples/app_config.yaml")
    add("code_review", config_instr, APP_CONFIG, flist(F_TLS), "examples/app_config.yaml")
    add("code_review", config_instr, APP_CONFIG, flist(F_LOG), "examples/app_config.yaml")

    # --- threat_model (3) ----------------------------------------------------
    tm_instr = (
        "Threat-model the following artifact (STRIDE-lite): identify assets, "
        "trust boundaries, attacker preconditions, impact, and mitigations."
    )
    add("threat_model", tm_instr, VULN_APP, flist(F_STRCPY, F_FMT), "examples/vuln_app.c")
    add("threat_model", tm_instr, APP_CONFIG, flist(F_TLS, F_DEBUG), "examples/app_config.yaml")
    add("threat_model", tm_instr, VULN_APP + "\n\n" + APP_CONFIG, flist(F_SECRET, F_LOG), "examples/")

    # --- remediation (4) ------------------------------------------------------
    rem_instr = (
        "Given this confirmed finding, produce a remediation plan including a "
        "regression test and safe next steps."
    )
    for f in (F_STRCPY, F_FMT, F_TLS, F_SECRET):
        add("remediation", rem_instr, json.dumps(f, indent=2), flist(f), f["file"])

    # --- detection (4) --------------------------------------------------------
    det_instr = (
        "For the following code and its known weakness, propose detection "
        "ideas for defenders and a regression test."
    )
    add("detection", det_instr, VULN_APP, flist(F_STRCPY), "examples/vuln_app.c")
    add("detection", det_instr, VULN_APP, flist(F_FMT), "examples/vuln_app.c")
    add("detection", det_instr, APP_CONFIG, flist(F_TLS), "examples/app_config.yaml")
    add("detection", det_instr, APP_CONFIG, flist(F_DEBUG), "examples/app_config.yaml")

    # --- report (2) -----------------------------------------------------------
    rep_instr = (
        "Write a structured findings summary for an authorized security review "
        "of the following artifact."
    )
    add("report", rep_instr, VULN_APP, flist(F_STRCPY, F_FMT, F_SECRET), "examples/vuln_app.c")
    add("report", rep_instr, APP_CONFIG, flist(F_DEBUG, F_TLS, F_LOG), "examples/app_config.yaml")

    # --- lab_recon (1) ---------------------------------------------------------
    add(
        "lab_recon",
        "Plan reconnaissance and enumeration for the authorized lab range 10.10.10.0/24 and pair it with detection opportunities.",
        "Authorized lab scope from the rules of engagement: 10.10.10.0/24, isolated training range.",
        payload(plans=[plan_t1046()]),
        "examples/ctf_brief.md",
    )

    # --- ctf_writeup (2) --------------------------------------------------------
    ctf_finding = finding(
        title="Juice Shop login form vulnerable to SQL injection (training app)",
        file="10.10.10.15 (lab Juice Shop)",
        lines="n/a",
        evidence="In the authorized lab CTF, the Juice Shop login form accepts input that alters the backend SQL query, allowing authentication bypass as documented in the challenge writeup.",
        severity="high",
        confidence=0.9,
        preconditions="Authorized access to the lab instance at 10.10.10.15; the app is vulnerable by design.",
        impact="Within the lab: authentication bypass and access to other user accounts, demonstrating the OWASP A03 Injection risk.",
        remediation="Use parameterized queries/prepared statements for authentication, add server-side input validation, and never concatenate user input into SQL.",
        regression_test="Automated test asserting the login endpoint rejects classic injection strings and only succeeds with valid credentials.",
        detection_idea="WAF/ModSecurity OWASP CRS SQLi rules; alert on SQL error messages in HTTP responses; query-log anomaly detection on the auth table.",
        limitations="Documented against a training target in the lab only; steps are intentionally high level.",
        safe_next_steps="Reset the lab instance, file the writeup, and map the exercise to detection content for the blue team.",
    )
    add(
        "ctf_writeup",
        "Write a step-by-step writeup for solving the OWASP Juice Shop 'Login Admin' challenge in our authorized CTF lab, focused on root cause and defender takeaways.",
        CTF_BRIEF,
        payload(findings=[ctf_finding]),
        "examples/ctf_brief.md",
    )
    add(
        "ctf_writeup",
        "Document the enumeration phase of the authorized Juice Shop CTF: what a defender would see and how to detect it.",
        CTF_BRIEF,
        payload(findings=[ctf_finding], plans=[plan_t1046()]),
        "examples/ctf_brief.md",
    )

    # --- attack_emulation (2) ---------------------------------------------------
    add(
        "attack_emulation",
        "Emulate ATT&CK technique T1059 (Command and Scripting Interpreter) in the authorized lab and document detection opportunities and cleanup.",
        "Authorized emulation request: instrumented lab VM at 192.168.56.10, purple-team exercise.",
        payload(plans=[plan_t1059()]),
        "examples/ctf_brief.md",
    )
    add(
        "attack_emulation",
        "Emulate ATT&CK technique T1046 (Network Service Discovery) against the authorized lab range 10.10.10.0/24 with detection opportunities and cleanup.",
        "Authorized emulation request: isolated training range 10.10.10.0/24, purple-team exercise.",
        payload(plans=[plan_t1046()]),
        "examples/ctf_brief.md",
    )

    return examples


def main() -> None:
    raw_dir = Path("data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / "seed_dataset.jsonl"

    examples = build_examples()
    validated = [TrainingExample(**e) for e in examples]
    with open(raw_path, "w", encoding="utf-8") as fh:
        for example in validated:
            fh.write(example.model_dump_json() + "\n")
    print(f"wrote {len(validated)} validated seed records to {raw_path}")

    result = curate(raw_dir=raw_dir, backend=MockBackend())
    print(
        f"curated dataset {result.version}: emitted={result.emitted} "
        f"skipped={result.skipped_not_approved} invalid={result.rejected_invalid} "
        f"out_of_scope={result.rejected_out_of_scope}"
    )
    print(f"dataset file: {result.dataset_path}")


if __name__ == "__main__":
    main()
