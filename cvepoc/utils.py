"""
Utility functions for cvelistV5 PoC
"""

import semver
import json
from .base import Status

__all__ = ["read_cve", "match_name", "match_vendor", "check_affected"]

def read_cve(filename: str) -> dict:
    """Read CVE file

    Args:
        filename (str): CVE file path

    Returns:
        dict: CVE data
    """
    with open(filename, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

def match_name(name: str, target: str) -> bool:
    """Match product name

    Args:
        name (str): product name
        product (str): product name

    Returns:
        bool: True if name matches product
    """

    return name.lower() == target.lower()


def match_vendor(vendor: str | None, target: str | None) -> bool:
    """Match vendor name

    Args:
        vendor (str | None): vendor name
        target (str | None): target vendor name

    Returns:
        bool: True if vendor matches target vendor
    """

    if target is None:
        return True

    if vendor is None or vendor == "*" or vendor == "n/a":
        return False

    return vendor.lower() == target.lower()

def check_affected(versions: dict, target: str, default_status: Status) -> Status:
    """Match product version

    Args:
        versions (dict): product version
        target (str): product targetversion
        default_status (str): default status

    Returns:
        str: status of product version
    """
    if versions == []:
        return default_status

    for version in versions:
        if semver.Version.is_valid(version["version"]):
            if "lessThanOrEqual" in version:
                if semver.compare(version["lessThanOrEqual"], target) >= 0:
                    return Status.AFFECTED
            elif "lessThan" in version:
                if semver.compare(version["lessThan"], target) > 0:
                    return Status.AFFECTED
            elif semver.compare(version["version"], target) == 0:
                return Status.AFFECTED
        else:
            if version["version"] == target:
                if version["status"] == "affected":
                    return Status.AFFECTED
                elif version["status"] == "unaffected":
                    return Status.NOT_AFFECTED

    return Status.NOT_AFFECTED