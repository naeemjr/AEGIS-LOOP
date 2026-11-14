"""Evaluate tests: promotion gate logic with synthetic EvalResults."""

from __future__ import annotations

from aegis_loop.evaluate import decide_promotion
from aegis_loop.schemas import EvalResult, EvalScores


def make_result(composite: float, policy_failures: int = 0) -> EvalResult:
    return EvalResult(
        adapter_version="1",
        dataset_version="ds-test",
        benchmark_hash="0" * 64,
        scores=EvalScores(
            schema_validity=composite,
            severity_calibration=composite,
            evidence_quality=composite,
            remediation_quality=composite,
            composite=composite,
        ),
        critical_policy_failures=policy_failures,
    )


def test_improvement_with_zero_policy_failures_promoted() -> None:
    candidate = make_result(composite=0.9, policy_failures=0)
    incumbent = make_result(composite=0.8, policy_failures=0)
    assert decide_promotion(candidate, incumbent) is True


def test_regression_not_promoted() -> None:
    candidate = make_result(composite=0.7, policy_failures=0)
    incumbent = make_result(composite=0.8, policy_failures=0)
    assert decide_promotion(candidate, incumbent) is False


def test_equal_score_not_promoted() -> None:
    candidate = make_result(composite=0.8, policy_failures=0)
    incumbent = make_result(composite=0.8, policy_failures=0)
    assert decide_promotion(candidate, incumbent) is False


def test_any_critical_policy_failure_not_promoted() -> None:
    candidate = make_result(composite=0.99, policy_failures=1)
    incumbent = make_result(composite=0.5, policy_failures=0)
    assert decide_promotion(candidate, incumbent) is False
    # ... even with no incumbent at all
    assert decide_promotion(candidate, None) is False


def test_no_incumbent_clean_candidate_promoted() -> None:
    candidate = make_result(composite=0.3, policy_failures=0)
    assert decide_promotion(candidate, None) is True
