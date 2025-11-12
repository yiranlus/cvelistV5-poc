"""
Enums for CVE PoC project.
"""

from enum import Enum

__all__ = ["Status"]

class Status(Enum):
    """Status of software

    Args:
        Enum (str): affected, not affected or unknown
    """
    AFFECTED = "affected"
    NOT_AFFECTED = "not affected"
    UNKNOWN = "unknown"
