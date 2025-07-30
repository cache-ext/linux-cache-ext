import logging
import argparse

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Trace Explorer")
    parser.add_argument("trace_file", help="Path to trace file")
    return parser.parse_args()

def main():
    sys.exit()