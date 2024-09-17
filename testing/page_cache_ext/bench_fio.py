import sys
import json
from typing import Dict, List
import logging
import argparse

from bench_lib import *

log = logging.getLogger(__name__)


class FioBenchmark(BenchmarkFramework):

    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("fio_benchmark", benchresults_cls, cli_args)

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--target-file", type=str, required=True, help="File to benchmark against."
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("iteration", [1, 2, 3], configs)
        configs = add_config_option("workload", ["randread"], configs)
        configs = add_config_option("runtime_seconds", [60], configs)
        configs = add_config_option("nr_threads", [8], configs)
        configs = add_config_option(
            "cgroup_size", [5 * GiB, 10 * GiB, 20 * GiB], configs
        )
        configs = add_config_option(
            "cgroup_name", [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP], configs
        )

        return configs

    def benchmark_prepare(self, config):
        log.info("Dropping page cache")
        drop_page_cache()
        log.info(
            "Setting up cgroup %s with size %s",
            config["cgroup_name"],
            format_bytes_str(config["cgroup_size"]),
        )
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def benchmark_cmd(self, config):
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            f"memory:{config['cgroup_name']}",
            "fio",
            "--direct=0",
            "--name=test",
            f"--filename={self.args.target_file}",
            f"--rw={config['workload']}",
            "--time_based",
            f"--runtime={config['runtime_seconds']}",
            f"--numjobs={config['nr_threads']}",
            "--bs=4k",
            "--group_reporting",
            "--output-format=json",
        ]
        return cmd

    def parse_results(self, stdout: str) -> BenchResults:
        # parse fio output
        fio_results = json.loads(stdout)
        return BenchResults(fio_results)

    def after_benchmark(self, config):
        log.info("Deleting cgroup %s", config["cgroup_name"])
        delete_cgroup(config["cgroup_name"])


def main():
    global log
    logging.basicConfig(level=logging.INFO)

    disable_swap()
    disable_smt()

    fio_bench = FioBenchmark()
    fio_bench.benchmark()


if __name__ == "__main__":
    sys.exit(main())
