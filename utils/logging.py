"""Safe application logging defaults."""

import logging


def configure_logging(level: str) -> None:
    """Configure structured, source-free process logging."""
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
