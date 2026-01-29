"""Audit logging — records who did what and when."""

import logging
import os
from datetime import datetime

LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "audit.log")

_logger = logging.getLogger("audit")
_logger.setLevel(logging.INFO)

if not _logger.handlers:
    handler = logging.FileHandler(LOG_PATH)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
    _logger.addHandler(handler)


def log_event(user: str, action: str, details: str = ""):
    _logger.info(f"user={user} | action={action} | {details}")
