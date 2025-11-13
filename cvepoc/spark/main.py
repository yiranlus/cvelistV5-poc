"""
Spark version of cvepoc
"""

import sys
from glob import glob
import click
from pyspark import SparkContext, SparkConf
import os

from ..base import Status
from ..utils import read_cve, match_name, check_affected, match_vendor

def match_containers(containers: list, product: str, vendor: str, version: str) -> list:
    result = []
    for container in containers:
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
                result.append((
                       check_affected(container.get("versions", []),
                                      version,
                                      default_status),
                       product,
                       container["vendor"],
                       version)
                )
        except KeyError:
            pass
    return result


@click.command()
@click.option("-m", "--master", default="local[*]", help="Spark master URL")
@click.option("-i", "--input",
              type=click.Path(exists=True, file_okay=False, dir_okay=True),
              required=True, help="cves directory")
@click.option("-p", "--product",
              type=click.STRING,
              required=True, help="product name")
@click.option("-e", "--vendor",
              type=click.STRING,
              default=None, required=False, help="vendor name")
@click.option("-r", "--version",
              type=click.STRING,
              required=True, help="product version")
def main_cli(master: str, input: str, product: str, vendor: str, version: str):
    """CLI interface for cvelistV5 PoC tool.

    Args:
        master (str): Spark master URL
        input (str): The input directory.
        product (str): The product name.
        vendor (str): The vendor name.
        version (str): The product version.
        n (int): Number of processes to use.
    """
    conf = SparkConf().setAppName(sys.argv[0]).setMaster(master)
    sc = SparkContext(conf=conf)
    input_abs = os.path.abspath(input)

    filelist = glob(f"{input_abs}/**/CVE-*.json", recursive=True)
    filelist_dist = sc.parallelize(filelist)

    mapped_entries = filelist_dist.map(
        read_cve
    ).map(
        lambda data: (
            data["containers"]["cna"]["affected"] if (
                "containers" in data
                and "cna" in data["containers"]
                and "affected" in data["containers"]["cna"]
            ) else []
        )
    ).map(
        lambda containers: (match_containers(containers, product, vendor, version))
    )

    result = filelist_dist.zip(mapped_entries).filter(
        lambda entry: entry[1] != []
    )

    for file_path, matches in result.collect():
        for status, prod, vendor, version in matches:
            print(f"{os.path.basename(file_path)}: {status.value} for {prod} {version} by {vendor}")

    sc.stop()
