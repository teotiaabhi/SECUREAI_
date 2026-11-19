import structlog
import logging
import re
import sys


def _mask_pii_processor(logger, method_name, event_dict):
    """Mask emails and IP addresses in log output."""
    for key in list(event_dict.keys()):
        val = event_dict[key]
        if isinstance(val, str):
            val = re.sub(
                r'([a-zA-Z0-9])[a-zA-Z0-9._%+-]*@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
                r'\1***@\2', val
            )
            val = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}', r'\1***', val)
            event_dict[key] = val
    return event_dict


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO

    # Shared pre-chain processors for foreign (stdlib) log records
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
        _mask_pii_processor,
    ]

    renderer = structlog.dev.ConsoleRenderer() if debug else structlog.processors.JSONRenderer()

    # Configure structlog to output through stdlib logging so that BOTH
    # structlog bound loggers and plain stdlib loggers share the same
    # formatting pipeline and handler.
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.dev.set_exc_info,
            structlog.processors.TimeStamper(fmt="iso"),
            _mask_pii_processor,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Single handler that formats ALL log records (both structlog and stdlib)
    # through structlog processors.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Silence noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str = "secureai"):
    return structlog.get_logger(name)
