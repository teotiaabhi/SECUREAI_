"""
AIValidationQueue — circuit-breaker-protected AI validation with
priority ordering, token budget enforcement, and retry logic.
"""

import asyncio
import logging
import time
from typing import Callable, Dict, List, Optional

from app.services.metrics import get_metrics

logger = logging.getLogger("orchestration.ai_validation_queue")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class CircuitBreaker:
    """Simple circuit breaker for AI provider endpoints."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ):
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._failure_count = 0
        self._last_failure_time: Optional[float] = None
        self._is_open = False

    @property
    def is_open(self) -> bool:
        if not self._is_open:
            return False
        # Check if recovery period has elapsed
        if self._last_failure_time is not None:
            elapsed = time.monotonic() - self._last_failure_time
            if elapsed >= self._recovery_timeout:
                self._is_open = False
                self._failure_count = 0
                logger.info("Circuit breaker closed (recovery period elapsed)")
                return False
        return True

    def record_success(self) -> None:
        self._failure_count = 0
        self._is_open = False

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self._failure_threshold:
            self._is_open = True
            logger.warning(
                "Circuit breaker opened after %d failures",
                self._failure_count,
            )


class AIValidationQueue:
    """Manages AI validation of scan findings with circuit breakers and budgets."""

    def __init__(
        self,
        max_concurrent: int = 5,
        max_validations: int = 20,
        max_tokens: int = 50000,
        max_retries: int = 2,
    ):
        self._max_concurrent = max_concurrent
        self._max_validations = max_validations
        self._max_tokens = max_tokens
        self._max_retries = max_retries
        self._circuit_breakers: Dict[str, CircuitBreaker] = {}
        self._tokens_used = 0

    def _get_circuit_breaker(self, provider: str) -> CircuitBreaker:
        if provider not in self._circuit_breakers:
            self._circuit_breakers[provider] = CircuitBreaker()
        return self._circuit_breakers[provider]

    async def validate_findings(
        self,
        findings: list,
        cancel_event: Optional[asyncio.Event] = None,
        progress_callback: Optional[Callable] = None,
    ) -> list:
        """Validate high-severity findings using AI, with an overall timeout."""
        from app.core.config import get_settings
        settings = get_settings()
        try:
            return await asyncio.wait_for(
                self._do_validate_findings(findings, cancel_event, progress_callback),
                timeout=settings.AI_TOTAL_TIMEOUT_PER_SCAN,
            )
        except asyncio.TimeoutError:
            logger.warning("AI validation timed out — returning findings as unvalidated")
            return findings

    async def _do_validate_findings(
        self,
        findings: list,
        cancel_event: Optional[asyncio.Event] = None,
        progress_callback: Optional[Callable] = None,
    ) -> list:
        """Validate high-severity findings using AI.

        Uses the existing engine.ai_validation module with added:
        - Circuit breaker protection per provider
        - Token budget enforcement
        - Priority-based validation order
        - Retry with exponential backoff
        - Cancellation support

        Args:
            findings: List of EngineFinding or RuleFinding objects.
            cancel_event: asyncio.Event for cancellation.
            progress_callback: Optional callback(validated_count, total).

        Returns:
            The findings list with confidence adjusted based on AI validation.
        """
        from engine.ai_validation import validate_finding_with_ai, _get_ai_config

        ai_config = _get_ai_config()
        metrics = get_metrics()
        if not ai_config.get("url") or not ai_config.get("token"):
            logger.info("AI validation skipped: no API configured")
            return findings

        # Filter findings that need validation
        to_validate = [
            f for f in findings
            if getattr(f, "requires_ai_validation", False)
        ]

        if not to_validate:
            logger.info("No findings require AI validation")
            return findings

        # Sort by severity priority (critical first)
        to_validate.sort(
            key=lambda f: (
                SEVERITY_ORDER.get(getattr(f, "severity", "info"), 4),
                -getattr(f, "confidence", 0),
            )
        )

        # Take top N
        to_validate = to_validate[:self._max_validations]
        total = len(to_validate)

        logger.info("AI validating %d findings", total)

        semaphore = asyncio.Semaphore(self._max_concurrent)
        validated_count = 0
        provider = ai_config.get("url", "default")
        cb = self._get_circuit_breaker(provider)

        async def _validate_one(finding) -> None:
            nonlocal validated_count

            if cancel_event and cancel_event.is_set():
                return

            # Check circuit breaker
            if cb.is_open:
                logger.debug("Circuit breaker open, skipping validation")
                metrics.ai_validations_total.inc({"status": "skipped"})
                return

            # Check token budget
            if self._tokens_used >= self._max_tokens:
                logger.info("Token budget exhausted (%d/%d)", self._tokens_used, self._max_tokens)
                metrics.ai_validations_total.inc({"status": "skipped"})
                return

            async with semaphore:
                result = None
                last_exc = None

                _val_start = time.monotonic()
                for attempt in range(self._max_retries + 1):
                    if cancel_event and cancel_event.is_set():
                        return

                    try:
                        # Truncate code snippet before sending to AI
                        from app.core.config import get_settings
                        _settings = get_settings()
                        snippet = getattr(finding, 'code_snippet', None) or getattr(finding, 'snippet', None)
                        if snippet and len(snippet) > _settings.AI_SNIPPET_MAX_CHARS:
                            finding.code_snippet = snippet[:_settings.AI_SNIPPET_MAX_CHARS]

                        result = await validate_finding_with_ai(finding, ai_config)
                        if result is not None:
                            cb.record_success()
                            # Estimate token usage (~300 tokens per validation)
                            self._tokens_used += 300
                            metrics.ai_validations_total.inc({"status": "success"})
                            metrics.ai_validation_seconds.observe(time.monotonic() - _val_start)
                            break
                    except Exception as exc:
                        last_exc = exc
                        cb.record_failure()
                        if attempt < self._max_retries:
                            backoff = 2 ** attempt
                            logger.debug(
                                "AI validation retry %d/%d after %ds: %s",
                                attempt + 1, self._max_retries, backoff, exc,
                            )
                            await asyncio.sleep(backoff)

                if result is None:
                    if last_exc:
                        logger.warning(
                            "AI validation failed for %s after %d retries: %s",
                            getattr(finding, "rule_id", "?"),
                            self._max_retries,
                            last_exc,
                        )
                    metrics.ai_validations_total.inc({"status": "failure"})
                    return

                # Apply confidence adjustments
                finding.ai_validated = True
                finding.ai_confidence = float(result.get("confidence", 50))

                if result.get("confirmed"):
                    finding.confidence = min(100.0, finding.confidence + 10.0)
                else:
                    finding.confidence = max(5.0, finding.confidence - 30.0)

                validated_count += 1
                if progress_callback:
                    progress_callback(validated_count, total)

        # Run all validations concurrently
        tasks = [_validate_one(f) for f in to_validate]
        await asyncio.gather(*tasks, return_exceptions=True)

        logger.info(
            "AI validation complete: %d/%d validated, %d tokens used",
            validated_count, total, self._tokens_used,
        )
        return findings
