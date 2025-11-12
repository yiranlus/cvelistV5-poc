"""
CVE processing module
"""
from multiprocessing import Queue
import json, os

from .base import Status
from .utils import match_name, check_affected, match_vendor

def process_CVE(q: Queue, filelist: list[str], product: str, version: str, vendor: str | None) -> None:
    """Process CVE files

    Args:
        q (Queue): a multiprocessing queue
        filelist (list[str]): a list of CVE file paths
        product (str): the product name
        version (str): the product version
        vendor (str): the vendor name
    """

    for filename in filelist:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

            # Check if there is data["containers"]["cna"]["affected"]
            if (
                "containers" in data
                and "cna" in data["containers"]
                and "affected" in data["containers"]["cna"]
            ):
                # Iterate over each affected product
                for container in data["containers"]["cna"]["affected"]:

                    # Set default status
                    default_status = Status.UNKNOWN
                    if "defaultStatus" in container:
                        if container["defaultStatus"] == "affected":
                            default_status = Status.AFFECTED
                        elif container["defaultStatus"] == "unaffected":
                            default_status = Status.NOT_AFFECTED

                    try:
                        if (
                            match_name(container["product"], product)
                            and match_vendor(container["vendor"], vendor)
                        ):
                            q.put((os.path.basename(filename),
                                check_affected(container.get("versions", []),
                                                version,
                                                default_status),
                                product,
                                version))
                    except KeyError:
                        pass