"""BDD coverage for the temporary AI validation feature flag."""

from types import SimpleNamespace

from app.orchestration.scan_orchestrator import should_run_ai_validation


def test_ai_validation_is_disabled_by_default():
    """Given AI credentials, when the feature flag is off, AI is not called."""
    settings = SimpleNamespace(
        AI_VALIDATION_ENABLED=False,
        PPLX_API_KEY="configured",
        HF_API_TOKEN="configured",
    )

    assert should_run_ai_validation(settings, [object()]) is False


def test_ai_validation_runs_only_when_explicitly_enabled():
    """Given AI credentials, when explicitly enabled, the phase may run."""
    settings = SimpleNamespace(
        AI_VALIDATION_ENABLED=True,
        PPLX_API_KEY="configured",
        HF_API_TOKEN="",
    )

    assert should_run_ai_validation(settings, [object()]) is True
