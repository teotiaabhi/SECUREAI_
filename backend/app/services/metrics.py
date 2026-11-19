"""
Observability metrics collector -- thread-safe, in-memory, zero external deps.

Implements Prometheus text exposition format (OpenMetrics-compatible) with:
- Counters (monotonically increasing)
- Histograms (bucketed observation distributions)
- Gauges (point-in-time values)

All metrics are labeled and rendered via format_prometheus() for the /metrics endpoint.
No prometheus_client package required.
"""

import threading
import time
from collections import defaultdict
from functools import lru_cache
from typing import Dict, List, Optional, Tuple


# ── Histogram bucket boundaries ──────────────────────────────
DEFAULT_BUCKETS = (0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0)


class Counter:
    """Monotonically increasing counter with label support."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._values: Dict[Tuple[str, ...], float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        key = self._labels_key(labels)
        with self._lock:
            self._values[key] += value

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        key = self._labels_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def format(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with self._lock:
            if not self._values:
                lines.append(f"{self.name} 0")
            else:
                for label_key, value in sorted(self._values.items()):
                    label_str = self._format_labels(label_key)
                    lines.append(f"{self.name}{label_str} {value}")
        return "\n".join(lines)

    @staticmethod
    def _labels_key(labels: Optional[Dict[str, str]]) -> Tuple[str, ...]:
        if not labels:
            return ()
        return tuple(sorted(labels.items()))

    @staticmethod
    def _format_labels(key: Tuple[str, ...]) -> str:
        if not key:
            return ""
        pairs = ",".join(f'{k}="{v}"' for k, v in key)
        return "{" + pairs + "}"


class Histogram:
    """Histogram with configurable buckets and label support."""

    def __init__(self, name: str, help_text: str, buckets: Tuple[float, ...] = DEFAULT_BUCKETS):
        self.name = name
        self.help_text = help_text
        self.buckets = buckets
        # Per label-set: {bucket_bound: count}
        self._bucket_counts: Dict[Tuple[str, ...], Dict[float, int]] = defaultdict(
            lambda: {b: 0 for b in self.buckets}
        )
        self._sums: Dict[Tuple[str, ...], float] = defaultdict(float)
        self._counts: Dict[Tuple[str, ...], int] = defaultdict(int)
        self._lock = threading.Lock()

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = Counter._labels_key(labels)
        with self._lock:
            if key not in self._bucket_counts:
                self._bucket_counts[key] = {b: 0 for b in self.buckets}
            for bound in self.buckets:
                if value <= bound:
                    self._bucket_counts[key][bound] += 1
            self._sums[key] += value
            self._counts[key] += 1

    def format(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with self._lock:
            for label_key in sorted(set(list(self._bucket_counts.keys()) +
                                        list(self._sums.keys()))):
                base_label = Counter._format_labels(label_key)
                # Bucket lines
                buckets = self._bucket_counts.get(label_key, {})
                cumulative = 0
                for bound in self.buckets:
                    cumulative += buckets.get(bound, 0)
                    if label_key:
                        # Merge le with existing labels
                        all_labels = dict(label_key)
                        all_labels["le"] = str(bound)
                        label_str = "{" + ",".join(
                            f'{k}="{v}"' for k, v in sorted(all_labels.items())
                        ) + "}"
                    else:
                        label_str = '{le="' + str(bound) + '"}'
                    lines.append(f"{self.name}_bucket{label_str} {cumulative}")

                # +Inf bucket
                total = self._counts.get(label_key, 0)
                if label_key:
                    all_labels = dict(label_key)
                    all_labels["le"] = "+Inf"
                    label_str = "{" + ",".join(
                        f'{k}="{v}"' for k, v in sorted(all_labels.items())
                    ) + "}"
                else:
                    label_str = '{le="+Inf"}'
                lines.append(f"{self.name}_bucket{label_str} {total}")

                # Sum and count
                sum_val = self._sums.get(label_key, 0.0)
                lines.append(f"{self.name}_sum{base_label} {sum_val}")
                lines.append(f"{self.name}_count{base_label} {total}")

        return "\n".join(lines)


class Gauge:
    """Point-in-time value gauge with label support."""

    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text
        self._values: Dict[Tuple[str, ...], float] = {}
        self._lock = threading.Lock()

    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = Counter._labels_key(labels)
        with self._lock:
            self._values[key] = value

    def inc(self, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        key = Counter._labels_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + value

    def dec(self, labels: Optional[Dict[str, str]] = None, value: float = 1.0) -> None:
        key = Counter._labels_key(labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) - value

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        key = Counter._labels_key(labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def format(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with self._lock:
            if not self._values:
                lines.append(f"{self.name} 0")
            else:
                for label_key, value in sorted(self._values.items()):
                    label_str = Counter._format_labels(label_key)
                    lines.append(f"{self.name}{label_str} {value}")
        return "\n".join(lines)


class MetricsCollector:
    """Central registry for all application metrics.

    Thread-safe. Accessed via get_metrics() singleton.
    """

    def __init__(self) -> None:
        # ── Counters ─────────────────────────────────────────
        self.scans_started_total = Counter(
            "secureai_scans_started_total",
            "Total scans started",
        )
        self.scans_completed_total = Counter(
            "secureai_scans_completed_total",
            "Total scans completed by status",
        )
        self.vulnerabilities_found_total = Counter(
            "secureai_vulnerabilities_found_total",
            "Total vulnerabilities found by severity",
        )
        self.webhook_events_total = Counter(
            "secureai_webhook_events_total",
            "Total webhook events received",
        )
        self.ai_validations_total = Counter(
            "secureai_ai_validations_total",
            "Total AI validation attempts",
        )

        # ── Histograms ───────────────────────────────────────
        self.scan_duration_seconds = Histogram(
            "secureai_scan_duration_seconds",
            "Scan duration in seconds",
        )
        self.webhook_processing_seconds = Histogram(
            "secureai_webhook_processing_seconds",
            "Webhook processing duration in seconds",
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )
        self.ai_validation_seconds = Histogram(
            "secureai_ai_validation_seconds",
            "AI validation duration in seconds per finding",
            buckets=(0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0),
        )

        # ── Gauges ───────────────────────────────────────────
        self.active_scans = Gauge(
            "secureai_active_scans",
            "Number of currently running scans",
        )
        self.queued_scans = Gauge(
            "secureai_queued_scans",
            "Number of scans waiting in queue",
        )
        self.memory_usage_percent = Gauge(
            "secureai_memory_usage_percent",
            "System memory usage percentage",
        )
        self.db_pool_active = Gauge(
            "secureai_db_pool_active_connections",
            "Active database pool connections",
        )

        # ── Worker metrics ──────────────────────────────────────
        self.worker_tasks_processed = Counter(
            "secureai_worker_tasks_processed_total",
            "Total tasks processed by workers",
        )
        self.worker_heartbeat_age = Gauge(
            "secureai_worker_heartbeat_age_seconds",
            "Seconds since last worker heartbeat",
        )
        self.dlq_size = Gauge(
            "secureai_dlq_size",
            "Number of tasks in the dead-letter queue",
        )

        # Uptime tracking
        self._start_time = time.time()

    def format_prometheus(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        sections = []

        # Uptime gauge (computed)
        uptime = time.time() - self._start_time
        sections.append(
            f"# HELP secureai_uptime_seconds Time since application start\n"
            f"# TYPE secureai_uptime_seconds gauge\n"
            f"secureai_uptime_seconds {uptime:.1f}"
        )

        # All registered metrics
        for metric in [
            self.scans_started_total,
            self.scans_completed_total,
            self.vulnerabilities_found_total,
            self.webhook_events_total,
            self.ai_validations_total,
            self.scan_duration_seconds,
            self.webhook_processing_seconds,
            self.ai_validation_seconds,
            self.active_scans,
            self.queued_scans,
            self.memory_usage_percent,
            self.db_pool_active,
            self.worker_tasks_processed,
            self.worker_heartbeat_age,
            self.dlq_size,
        ]:
            sections.append(metric.format())

        return "\n\n".join(sections) + "\n"


# ── Singleton accessor ───────────────────────────────────────

_metrics_instance: Optional[MetricsCollector] = None
_metrics_lock = threading.Lock()


def get_metrics() -> MetricsCollector:
    """Get or create the global MetricsCollector singleton."""
    global _metrics_instance
    if _metrics_instance is None:
        with _metrics_lock:
            if _metrics_instance is None:
                _metrics_instance = MetricsCollector()
    return _metrics_instance
