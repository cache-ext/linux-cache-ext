#!/usr/bin/env python3

import os
import sys
import time
import json
import random
import IPython
import logging
import argparse

from signal import SIGINT
from dataclasses import dataclass
from subprocess import Popen, PIPE, run

log = logging.getLogger(__name__)

KB = 1024
MB = 1024 * KB
GB = 1024 * MB

@dataclass
class Stats:
    """A simple dataclass to hold the stats of the workload"""
    read_count: int = 0
    write_count: int = 0
    read_time: int = 0
    write_time: int = 0

BPFTRACE_TMPL = """
// file: io_operations.bt
// Description: Tracks I/O operations and total time spent in I/O per PID and operation type.

tracepoint:block:block_rq_issue {
  // Store the start time using a composite key of device, sector, and PID

  @start[args->dev, args->sector] = nsecs;
}

tracepoint:block:block_rq_complete /@start[args->dev, args->sector]/{
  // Determine operation type using strncmp
  $op_type = strncmp(args->rwbs, "R", 1) == 0 ? "Read" : "Write";
  // Calculate latency
  $latency = nsecs - @start[args->dev, args->sector];
  // Sum up latencies and count I/Os based on PID and operation type
  @[$op_type, "Count"] += 1;
  @[$op_type, "Time"] += $latency;
  // Clean up the start time entry
  delete(@start[args->dev, args->sector]);
}

// Print the final results when the script exits
END {
  print(@); // Only printing the aggregated results
  clear(@start);
  clear(@);
}
"""


class FuncTimeTracer:
    def __init__(self):
        self.stats = Stats()
        self.process = None

    def start(self):
        if self.process:
            raise Exception("Process already started")
        cmd = ["sudo", "bpftrace", "-f", "json", "bpftrace_scripts/functime.bt"]
        # Start command and capture stdout
        self.process = Popen(cmd, stdout=PIPE, stderr=PIPE)

    def stop(self) -> Stats:
        # Stop the process
        if not self.process:
            raise Exception("Process not started")
        cmd = ["sudo", "kill", "-2", str(self.process.pid)]
        run(cmd, check=True)
        out, err = self.process.communicate()
        if err:
            log.error("Error running bpftrace: %s", err)
        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj["type"] != "map":
                continue
            func_name_to_nano = obj["data"]["@totalTime"]
            for func_name, nano in func_name_to_nano.items():
                print(f"Function: {func_name}, Time: {nano / 1e9} sec")
        print(str(out, "utf-8"))


class StatsTracer:
    """A simple class to trace the stats of the workload"""
    def __init__(self, pid: int):
        self.stats = Stats()
        self.pid = pid
        self.process = None

    def start(self):
        if self.process:
            raise Exception("Process already started")
        cmd = ["sudo", "bpftrace", "-f", "json", "-e", BPFTRACE_TMPL]
        # Start command and capture stdout
        self.process = Popen(cmd, stdout=PIPE, stderr=PIPE)

    def stop(self) -> Stats:
        # Stop the process
        if not self.process:
            raise Exception("Process not started")
        cmd = ["sudo", "kill", "-2", str(self.process.pid)]
        run(cmd, check=True)
        out, err = self.process.communicate()
        if err:
            log.error("Error running bpftrace: %s", err)
        # Each line is a JSON object

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj["type"] != "map":
                continue
            # Example: {"type": "map", "data": {"@": {"Write,Count": 25, "Read,Count": 80, "Read,Time": 15990424, "Write,Time": 134637870}}}
            map_data = obj["data"]["@"]
            for key, value in map_data.items():
                if key == "Read,Count":
                    self.stats.read_count = value
                elif key == "Write,Count":
                    self.stats.write_count = value
                elif key == "Read,Time":
                    self.stats.read_time = value
                elif key == "Write,Time":
                    self.stats.write_time = value
        return self.stats


def parse_args():
    parser = argparse.ArgumentParser("Test app")
    parser.add_argument(
        "--workingset-size",
        type=int,
        default=int(1.2 * GB),
        help="Specify the working set size",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=-1,
        help="Specify the number of iterations to run the test",
    )
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="Enable tracing workload",
        default=False,
    )
    return parser.parse_args()


def approx_equal(a, b, tolerance=0.1):
    return abs(a - b) <= tolerance * a


def create_test_file(path="test_dir/testfile", size_in_bytes=1 * GB):
    with open(path, "wb") as f:
        f.write(os.urandom(size_in_bytes))


def test_file_exists(path="test_dir/testfile", size_in_bytes=1 * GB):
    if not os.path.exists(path):
        return False
    return approx_equal(os.path.getsize(path), size_in_bytes)


def iterate_test_file_once(f):
    f.seek(0, os.SEEK_SET)
    while True:
        data = os.read(f.fileno(), 4 * KB)
        if not data:
            break

def iterate_test_file_once_randomly(f, number_of_pages: int, seed=42):
    # Use pread
    page_size = 4 * KB
    random.seed(seed)
    possible_offsets = [i * page_size for i in range(number_of_pages)]
    # Permute the offsets
    random.shuffle(possible_offsets)
    for offset in possible_offsets:
        os.pread(f.fileno(), page_size, offset)


def autodetect_mem_cgroup():
    with open("/proc/self/cgroup", "r") as f:
        lines = f.readlines()
    lines = [l.strip() for l in lines if l.strip()]
    return lines[0].split("/")[-1]


def parse_cgroup_mem_stat(filename):
    with open(filename, "r") as f:
        lines = f.readlines()
    stats = {}
    for line in lines:
        key, value = line.strip().split()
        stats[key] = int(value)
    return stats


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    cgroup = autodetect_mem_cgroup()
    cgroup_mem_stat_file = f"/sys/fs/cgroup/{cgroup}/memory.stat"
    cgroup_mem_stat = parse_cgroup_mem_stat(cgroup_mem_stat_file)
    start_scan, start_reclaim = cgroup_mem_stat["pgscan_direct"], cgroup_mem_stat["pgsteal_direct"]
    args = parse_args()
    log.info("Creating test file of size %d bytes", args.workingset_size)
    if not test_file_exists(size_in_bytes=args.workingset_size):
        create_test_file(size_in_bytes=args.workingset_size)
    log.info("Running test workload in a loop")
    log.info("Press Ctrl+C to stop the test")
    # Open the file and read it start to end in a loop
    with open("test_dir/testfile", "rb") as f:
        # fadvise random
        os.posix_fadvise(f.fileno(), 0, 0, os.POSIX_FADV_RANDOM)
        # Read in 4k increments, use read system call
        try:
            if args.iterations == -1:
                while True:
                    iterate_test_file_once(f)
            else:
                if not args.no_stats:
                    tracer = StatsTracer(os.getpid())
                    ftime_tracer = FuncTimeTracer()
                    tracer.start()
                    ftime_tracer.start()
                file_size = os.path.getsize("test_dir/testfile")
                page_size = 4 * KB
                file_size_in_pages = int(file_size // page_size)
                for iter in range(args.iterations):
                    print("Iteration: ", iter)
                    start_time = time.time()
                    iterate_test_file_once_randomly(f, file_size_in_pages)
                    end_time = time.time()
                    duration = end_time - start_time
                    print("Iteration took: %.2f seconds" % duration)
                if not args.no_stats:
                    ftime_tracer.stop()
                    stats = tracer.stop()
                    print("Stats: ")
                    print("Read time: %.1f sec, Write time: %d" %
                          (stats.read_time / 1e9, stats.write_time / 1e9))
                    avg_read_latency = stats.read_time / stats.read_count
                    print("Average read latency: %.1f us" % (avg_read_latency / 1e3))
                    # Get testfile size in bytes
                    file_size = os.path.getsize("test_dir/testfile")
                    page_size = 4 * 2 ** 10
                    file_size_in_pages = int(file_size // page_size)
                    total_accesses = args.iterations * file_size_in_pages
                    implied_hit_rate = (1 - (stats.read_count / total_accesses)) * 100
                    print("Implied hit rate: %.2f%%" % implied_hit_rate)
        except KeyboardInterrupt:
            if not args.no_stats:
                log.info("Exiting...")
                ftime_tracer.stop()
                tracer.stop()
                raise
    cgroup_mem_stat = parse_cgroup_mem_stat(cgroup_mem_stat_file)
    end_scan, end_reclaim = cgroup_mem_stat["pgscan_direct"], cgroup_mem_stat["pgsteal_direct"]
    scan_diff = end_scan - start_scan
    reclaim_diff = end_reclaim - start_reclaim
    reclaim_efficiency = (reclaim_diff / scan_diff) * 100
    log.info("Scanned: %d pages, Reclaimed: %d pages", scan_diff, reclaim_diff)
    log.info("Reclaim efficiency: %.2f%%", reclaim_efficiency)


if __name__ == "__main__":
    sys.exit(main())
