import os
import re
import logging
import argparse
import subprocess

from time import sleep
from bench_lib import *
from typing import Dict, List


log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []


def parse_io_trace_bench_results(stdout: str) -> Dict:
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
            pattern = r"(\w+ throughput) (\d+\.\d+) ops/sec"
            matches = re.findall(pattern, line)
            # Matches look like this:
            # [('UPDATE throughput', '0.00'),
            #  ('INSERT throughput', '12337.23'),
            #  ('READ throughput', '12369.98'),
            #  ('SCAN throughput', '0.00'),
            #  ('READ_MODIFY_WRITE throughput', '0.00'),
            #  ('total throughput', '24707.21')]
            assert len(matches) == 6, "Unexpected line pattern: %s" % line
            assert "total throughput" in matches[-1][0]
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
                    results["read_modify_write_throughput_avg"] = float(match[1])
                elif "total throughput" in match[0]:
                    results["throughput_avg"] = float(match[1])
                else:
                    raise Exception("Unknown throughput type: " + match[0])
            results["throughput_avg"] = float(matches[-1][1])
        elif "overall: UPDATE average latency" in line:
            # Parse latency
            pattern = r"(\w+ \w+ latency) (\d+\.\d+) ns"
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
                    results["read_modify_write_latency_avg"] = float(match[1])
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
                    results["read_modify_write_latency_p99"] = float(match[1])
                else:
                    raise Exception("Unknown latency metric: " + match[0])
    if not all(
        key in results for key in ["throughput_avg", "latency_avg", "latency_p99"]
    ):
        raise Exception("Could not parse results from stdout: \n" + stdout)
    return results


class IOTraceBenchmark(BenchmarkFramework):

    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("iotrace_benchmark", benchresults_cls, cli_args)
        if self.args.trace_temp_data_dir is None:
            self.args.trace_temp_data_dir = self.args.trace_data_dir + "_temp"
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.trace_temp_data_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--trace-data-dir",
            type=str,
            default="/mydata/linux/linux/testing/page_cache_ext/google_traces/data_cluster1_16TB_20240115_data-00000-of-00100",
            help="Trace data directory",
        )
        parser.add_argument(
            "--trace-temp-data-dir",
            type=str,
            default=None,
            help="Specify the temporary directory for IOTrace benchmarking. Default is <trace_data_dir>_temp",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            default="./page_cache_ext_sampling.out",
            help="Specify the path to the policy loader binary",
        )
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            default="/mydata/My-YCSB/build",
            help="Specify the directory containing the benchmark binary",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            default="trace_cluster1_16TB_20240115_data-00000-of-00100",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("runtime_seconds", [180], configs)
        configs = add_config_option("warmup_runtime_seconds", [60], configs)
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option(
            "cgroup_size", [15 * GiB], configs
        )
        configs = add_config_option(
            "cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs
            # "cgroup_name", [DEFAULT_CACHE_EXT_CGROUP], configs
        )
        configs = add_config_option("iteration", list(range(1, 15)), configs)
        return configs

    def benchmark_prepare(self, config):
        # rsync_folder(self.args.trace_data_dir, self.args.trace_temp_data_dir)
        drop_page_cache()
        disable_swap()
        disable_smt()

        # To ensure that writeback keeps up with the benchmark
        set_sysctl("vm.dirty_background_ratio", 10)
        set_sysctl("vm.dirty_ratio", 30)

        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def benchmark_cmd(self, config):
        bench_binary_dir = self.args.bench_binary_dir
        trace_temp_data_dir = self.args.trace_temp_data_dir
        bench_binary = os.path.join(bench_binary_dir, "run_io_trace")
        bench_file = "../io_trace/config/io_trace.yaml"
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        if not os.path.exists(bench_file):
            raise Exception("Benchmark file not found: %s" % bench_file)
        trace_file = "../%s.txt" % config["benchmark"]
        trace_file = os.path.abspath(os.path.join(trace_temp_data_dir, trace_file))
        if not os.path.exists(trace_file):
            raise Exception("Trace file not found: %s" % trace_file)
        with edit_yaml_file(bench_file) as bench_config:
            bench_config["io_trace"]["data_dir"] = trace_temp_data_dir
            bench_config["workload"]["trace_file"] = trace_file
            bench_config["workload"]["runtime_seconds"] = config["runtime_seconds"]
            bench_config["workload"]["warmup_runtime_seconds"] = config["warmup_runtime_seconds"]
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            bench_binary,
            bench_file,
        ]
        return cmd

    def after_benchmark(self, config):
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        drop_page_cache()
        sleep(2)
        enable_smt()
        
        # Reset to default
        set_sysctl("vm.dirty_background_ratio", 10)
        set_sysctl("vm.dirty_ratio", 20)

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_io_trace_bench_results(stdout)
        return BenchResults(results)


def main():
    global log
    ulimit(1000000)

    io_trace_bench = IOTraceBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(io_trace_bench.args.trace_data_dir):
        raise Exception(
            "IOTrace data directory not found: %s" % io_trace_bench.args.trace_data_dir
        )
    # Check that bench_binary_dir exists
    if not os.path.exists(io_trace_bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % io_trace_bench.args.bench_binary_dir
        )
    log.info("IOTrace DB directory: %s", io_trace_bench.args.trace_data_dir)
    log.info("IOTrace temp DB directory: %s", io_trace_bench.args.trace_temp_data_dir)
    io_trace_bench.benchmark()


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
