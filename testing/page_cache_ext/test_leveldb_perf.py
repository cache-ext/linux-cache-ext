import os
import re
import json
import uuid
import logging
import subprocess

from typing import Dict

log = logging.getLogger(__name__)
GiB = 2**30


def run(cmd, *args, **kwargs):
    # Set check=True
    kwargs['check'] = True
    return subprocess.run(cmd, *args, **kwargs)


def create_cache_ext_cgroup(limit_in_bytes=2*GiB):
    # Create cache_ext cgroup
    run(["sudo", "cgcreate", "-g", "memory:cache_ext_test"])

    # Set memory limit for cache_ext cgroup
    run(["sudo", "sh", "-c", "echo %d > /sys/fs/cgroup/cache_ext_test/memory.max" % limit_in_bytes])

    # Enable page cache extension for cache_ext cgroup
    run(["sudo", "sh", "-c", "echo -n '/cache_ext_test' > /proc/page_cache_ext_enabled_cgroup"])


def create_baseline_cgroup(limit_in_bytes=2*GiB):
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
    # Template:
    # === RocksDB Stats Start ===
    # rocksdb.block.cache.miss COUNT : 980
    # rocksdb.block.cache.hit COUNT : 20
    # rocksdb.block.cache.add COUNT : 980
    #
    # === RocksDB Stats End ===
    results = {}
    results["keys_failed"] = 0
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


def disable_smt():
    run(["sudo", "sh", "-c", "echo off > /sys/devices/system/cpu/smt/control"])


def main():
    bench_binary_dir = "/mydata/My-YCSB/build"

    create_cache_ext_cgroup()
    create_baseline_cgroup()
    disable_swap()
    disable_smt()

    all_results = []
    results_file = "results.json"
    if os.path.exists(results_file):
        all_results = load_json(results_file)

    num_iterations = 6
    for enable_mmap in [False]:
        for cgroup in ["cache_ext_test", "baseline_test"]:
            for i in range(num_iterations):
                log.info("Running iteration %d with cgroup %s", i, cgroup)
                # Reset the environment
                reset_database()
                drop_page_cache()
                # Run the benchmark
                cmd_env = os.environ.copy()
                if enable_mmap:
                    cmd_env["LEVELDB_MAX_MMAPS"] = "10000"
                cmd = ["taskset", "-c", "0-4",
                       "sudo", "cgexec", "-g", "memory:%s" % cgroup,
                       "./run_leveldb", "../leveldb/config/ycsb_a.yaml"]
                out = subprocess.check_output(cmd, cwd=bench_binary_dir,
                                              text=True, env=cmd_env)
                bench_results = parse_leveldb_bench_results(out)
                all_results.append({
                    "enable_mmap": enable_mmap,
                    "cgroup": cgroup,
                    "run_id": uuid.uuid4().hex,
                    "results": bench_results
                })
                # Save results
                save_json(results_file, all_results)


if __name__ == "__main__":
    main()
