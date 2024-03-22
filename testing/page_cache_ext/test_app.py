#!/usr/bin/env python3

import os
import sys
import random
import logging
import argparse


log = logging.getLogger(__name__)

KB = 1024
MB = 1024 * KB
GB = 1024 * MB


def parse_args():
    parser = argparse.ArgumentParser("Test app")
    parser.add_argument(
        "--workingset-size",
        type=int,
        default=int(1.2 * GB),
        help="Specify the working set size",
    )
    return parser.parse_args()


def approx_equal(a, b, tolerance=0.1):
    return abs(a - b) <= tolerance * a


def create_test_file(path="testfile", size_in_bytes=1 * GB):
    with open(path, "wb") as f:
        f.write(os.urandom(size_in_bytes))


def test_file_exists(path="testfile", size_in_bytes=1 * GB):
    if not os.path.exists(path):
        return False
    return approx_equal(os.path.getsize(path), size_in_bytes)


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    log.info("Creating test file of size %d bytes", args.workingset_size)
    if not test_file_exists(size_in_bytes=args.workingset_size):
        create_test_file(size_in_bytes=args.workingset_size)
    log.info("Running test workload in a loop")
    log.info("Press Ctrl+C to stop the test")
    # Open the file and read it start to end in a loop
    with open("testfile", "rb") as f:
        # Read in 4k increments, use read system call
        while True:
            f.seek(0, os.SEEK_SET)
            while True:
                data = os.read(f.fileno(), 4 * KB)
                if not data:
                    break


if __name__ == "__main__":
    sys.exit(main())
