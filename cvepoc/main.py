"""
CLI for cvelistV5 PoC
=====================

CLI interface for cvelistV5 proof of concept tool.
"""

import click
from glob import glob
import multiprocessing as mp
from multiprocessing.queues import Empty

from . import __version__
from .process import process_CVE

__all__ = ["main_cli"]

@click.command()
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
@click.option("-n", default=10, help="number of processes to use")
def main_cli(input: str, product: str, vendor: str, version: str, n: int):
    """CLI interface for cvelistV5 PoC tool.

    Args:
        input (str): The input directory.
        product (str): The product name.
        vendor (str): The vendor name.
        version (str): The product version.
        n (int): Number of processes to use.
    """

    filelist = glob(f"{input}/**/CVE-*.json", recursive=True)
    chunk_size = len(filelist) // n + 1

    mp.set_start_method('spawn')
    q = mp.Queue()

    print("Processing CVE files...")
    processes = []
    for i in range(n):
        p = mp.Process(target=process_CVE, args=(q, filelist[i*chunk_size:(i+1)*chunk_size], product, version, vendor))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
    print("Done!")

    while True:
        try:
            filename, status, product, version = q.get_nowait()
            print(f"{filename}: {status.value} for {product} {version}")
        except Empty:
            break

    q.close()
