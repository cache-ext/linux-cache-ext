import os
import re
import json
import uuid
import logging
import argparse
import subprocess

from time import sleep
from typing import Dict
from contextlib import suppress

log = logging.getLogger(__name__)
GiB = 2**30


def run(cmd, *args, **kwargs):
    # Set check=True
    kwargs['check'] = True
    return subprocess.run(cmd, *args, **kwargs)


def read_file(path: str):
    with open(path, "r") as f:
        return f.read().strip()


def write_file(path: str, data: str):
    with open(path, "w") as f:
        f.write(data)


def enable_cache_ext_for_cgroup(cgroup="cache_ext_test"):
    # echo -n "/cache_ext_test" > /proc/page_cache_ext_enabled_cgroup
    run(["echo", "-n", "/%s" % cgroup, ">",
         "/proc/page_cache_ext_enabled_cgroup"])


def recreate_cache_ext_cgroup(limit_in_bytes=2*GiB):
    with suppress(subprocess.CalledProcessError):
        run(["sudo", "cgdelete", "memory:cache_ext_test"])
    # Create cache_ext cgroup
    run(["sudo", "cgcreate", "-g", "memory:cache_ext_test"])

    # Set memory limit for cache_ext cgroup
    run(["sudo", "sh", "-c", "echo %d > /sys/fs/cgroup/cache_ext_test/memory.max" % limit_in_bytes])

    # Enable page cache extension for cache_ext cgroup
    run(["sudo", "sh", "-c", "echo -n '/cache_ext_test' > /proc/page_cache_ext_enabled_cgroup"])


def recreate_baseline_cgroup(limit_in_bytes=2*GiB):
    with suppress(subprocess.CalledProcessError):
        run(["sudo", "cgdelete", "memory:baseline_test"])

    # Create baseline cgroup
    run(["sudo", "cgcreate", "-g", "memory:baseline_test"])

    # Set memory limit for baseline cgroup
    run(["sudo", "sh", "-c",
         "echo %d > /sys/fs/cgroup/baseline_test/memory.max" % limit_in_bytes])


def drop_page_cache():
    run(["sudo", "sync"])
    run(["sudo", "sh", "-c", "echo 1 > /proc/sys/vm/drop_caches"])


def disable_swap():
    run(["sudo", "swapoff", "-a"])


def reset_database():
    # rsync -avpl --delete /mydata/leveldb_db_orig/ /mydata/leveldb_db/
    run(["rsync", "-avpl", "--delete", "/mydata/leveldb_orig/",
         "/mydata/leveldb_db/"])


def load_json(path: str):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path: str, data):
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=4)
    os.rename(tmp_path, path)


def parse_leveldb_bench_results(stdout: str) -> Dict:
    # Uniform: calculating overall performance metrics... (might take a while)
    # Uniform overall: UPDATE throughput 0.00 ops/sec, INSERT throughput 0.00 ops/sec, READ throughput 9038.24 ops/sec, SCAN throughput 0.00 ops/sec, READ_MODIFY_WRITE throughput 0.00 ops/sec, total throughput 9038.24 ops/sec
    # Uniform overall: UPDATE average latency 0.00 ns, UPDATE p99 latency 0.00 ns, INSERT average latency 0.00 ns, INSERT p99 latency 0.00 ns, READ average latency 109658.84 ns, READ p99 latency 145190.65 ns, SCAN average latency 0.00 ns, SCAN p99 latency 0.00 ns, READ_MODIFY_WRITE average latency 0.00 ns, READ_MODIFY_WRITE p99 latency 0.00 ns
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        elif "overall: UPDATE throughput" in line:
            # Parse throughput
            pattern = r'(\w+ throughput) (\d+\.\d+) ops/sec'
            matches = re.findall(pattern, line)
            # Matches look like this:
            # [('UPDATE throughput', '0.00'),
            #  ('INSERT throughput', '12337.23'),
            #  ('READ throughput', '12369.98'),
            #  ('SCAN throughput', '0.00'),
            #  ('READ_MODIFY_WRITE throughput', '0.00'),
            #  ('total throughput', '24707.21')]
            assert (len(matches) == 6), "Unexpected line pattern: %s" % line
            assert ("total throughput" in matches[-1][0])
            for match in matches:
                if "READ throughput" in match[0]:
                    results["read_throughput_avg"] = float(match[1])
                elif "INSERT throughput" in match[0]:
                    results["insert_throughput_avg"] = float(match[1])
                elif "UPDATE throughput" in match[0]:
                    results["update_throughput_avg"] = float(match[1])
                elif "SCAN throughput" in match[0]:
                    results["scan_throughput_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE throughput" in match[0]:
                    results["read_modify_write_throughput_avg"] = float(
                        match[1])
                elif "total throughput" in match[0]:
                    results["throughput_avg"] = float(match[1])
                else:
                    raise Exception("Unknown throughput type: " + match[0])
            results["throughput_avg"] = float(matches[-1][1])
        elif "overall: UPDATE average latency" in line:
            # Parse latency
            pattern = r'(\w+ \w+ latency) (\d+\.\d+) ns'
            matches = re.findall(pattern, line)
            # Matches look like this:
            # [('UPDATE average latency', '0.00'),
            #  ('UPDATE p99 latency', '0.00'),
            #  ('INSERT average latency', '80992.84'),
            #  ('INSERT p99 latency', '887726.24'),
            #  ('READ average latency', '1850251.43'),
            #  ('READ p99 latency', '6888407.68'),
            #  ('SCAN average latency', '0.00'),
            #  ('SCAN p99 latency', '0.00'),
            #  ('READ_MODIFY_WRITE average latency', '0.00'),
            #  ('READ_MODIFY_WRITE p99 latency', '0.00')]
            for match in matches:
                if "READ average latency" in match[0]:
                    results["read_latency_avg"] = float(match[1])
                    results["latency_avg"] = float(match[1])
                elif "INSERT average latency" in match[0]:
                    results["insert_latency_avg"] = float(match[1])
                elif "UPDATE average latency" in match[0]:
                    results["update_latency_avg"] = float(match[1])
                elif "SCAN average latency" in match[0]:
                    results["scan_latency_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE average latency" in match[0]:
                    results["read_modify_write_latency_avg"] = float(
                        match[1])
                elif "READ p99 latency" in match[0]:
                    results["read_latency_p99"] = float(match[1])
                    results["latency_p99"] = float(match[1])
                elif "INSERT p99 latency" in match[0]:
                    results["insert_latency_p99"] = float(match[1])
                elif "UPDATE p99 latency" in match[0]:
                    results["update_latency_p99"] = float(match[1])
                elif "SCAN p99 latency" in match[0]:
                    results["scan_latency_p99"] = float(match[1])
                elif "READ_MODIFY_WRITE p99 latency" in match[0]:
                    results["read_modify_write_latency_p99"] = float(
                        match[1])
                else:
                    raise Exception("Unknown latency metric: " + match[0])
    if not all(key in results for key in ["throughput_avg", "latency_avg", "latency_p99"]):
        raise Exception("Could not parse results from stdout: \n" + stdout)
    return results


class CacheExtPolicy:
    def __init__(self, cgroup: str, loader_path: str, watch_dir: str):
        self.cgroup_path = "/sys/fs/cgroup/%s" % cgroup
        self.loader_path = loader_path
        self.watch_dir = watch_dir
        self.has_started = False
        self._policy_thread = None

    def start(self):
        if self.has_started:
            raise Exception("Policy already started")
        self.has_started = True
        cmd = ["sudo", self.loader_path, "--watch_dir", self.watch_dir]
        self._policy_thread = subprocess.Popen(cmd,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
        sleep(2)
        if self._policy_thread.poll() is not None:
            raise Exception("Policy thread exited unexpectedly: %s" %
                            self._policy_thread.stderr.read())

    def stop(self):
        if not self.has_started:
            raise Exception("Policy not started")
        cmd = ["sudo", "kill", "-2", str(self._policy_thread.pid)]
        run(cmd)
        out, err = self._policy_thread.communicate()
        log.info("Policy thread stdout: %s", out)
        log.info("Policy thread stderr: %s", err)
        self.has_started = False
        self._policy_thread = None


def disable_smt():
    run(["sudo", "sh", "-c", "echo off > /sys/devices/system/cpu/smt/control"])


CLEANUP_TASKS = []


def parse_args():
    parser = argparse.ArgumentParser("Benchmark LevelDB with cache_ext")
    parser.add_argument(
        "--leveldb-db",
        type=str,
        default="/mydata/leveldb_db",
        help="Specify the directory to watch for cache_ext",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    bench_binary_dir = "/mydata/My-YCSB/build"
    leveldb_db_dir = os.path.realpath(args.leveldb_db)
    cgroup_size_in_bytes = 5 * GiB

    # Sanity check that dir exists
    if not os.path.exists(leveldb_db_dir):
        raise Exception("LevelDB DB directory not found: %s" % leveldb_db_dir)
    log.info("LevelDB DB directory: %s", leveldb_db_dir)

    disable_swap()
    disable_smt()

    all_results = []
    results_file = "results.json"
    if os.path.exists(results_file):
        all_results = load_json(results_file)

    policy_loader_binary = "./page_cache_ext_sampling.out"
    if not os.path.exists(policy_loader_binary):
        raise Exception("Policy loader binary not found: %s" %
                        policy_loader_binary)
    cache_ext_policy = CacheExtPolicy("cache_ext_test", policy_loader_binary,
                                      leveldb_db_dir)

    CLEANUP_TASKS.append(lambda: cache_ext_policy.stop())
    num_iterations = 1
    for enable_mmap in [False]:
        for benchmark in ["ycsb_c"]:
            for cgroup in ["cache_ext_test", "baseline_test"]:
                for i in range(num_iterations):
                    if cgroup == "cache_ext_test":
                        recreate_cache_ext_cgroup(limit_in_bytes=cgroup_size_in_bytes)
                    else:
                        recreate_baseline_cgroup(limit_in_bytes=cgroup_size_in_bytes)
                    log.info("Running iteration %d with cgroup %s", i, cgroup)
                    # Reset the environment
                    reset_database()
                    drop_page_cache()
                    if cgroup == "cache_ext_test":
                        log.info("Starting cache_ext policy")
                        cache_ext_policy.start()
                    # Run the benchmark
                    cmd_env = os.environ.copy()
                    if enable_mmap:
                        cmd_env["LEVELDB_MAX_MMAPS"] = "10000"
                    bench_file = "../leveldb/config/%s.yaml" % benchmark
                    cmd = ["taskset", "-c", "0-5",
                           "sudo", "cgexec", "-g", "memory:%s" % cgroup,
                           "./run_leveldb", bench_file]
                    out = subprocess.check_output(cmd, cwd=bench_binary_dir,
                                                  text=True, env=cmd_env)
                    bench_results = parse_leveldb_bench_results(out)
                    all_results.append({
                        "enable_mmap": enable_mmap,
                        "cgroup": cgroup,
                        "cgroup_size_in_bytes": cgroup_size_in_bytes,
                        "run_id": uuid.uuid4().hex,
                        "benchmark": benchmark,
                        "results": bench_results
                    })
                    # Save results
                    save_json(results_file, all_results)
                    if cgroup == "cache_ext_test":
                        log.info("Stopping cache_ext policy")
                        cache_ext_policy.stop()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
