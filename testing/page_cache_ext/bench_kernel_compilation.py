import argparse
import logging
import os
from typing import List, Dict

from bench_lib import *

log = logging.getLogger(__name__)

CLEANUP_TASKS = []


class KernelCompilationBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("kernel_compilation_benchmark", benchresults_cls, cli_args)
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.data_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--data-dir",
            type=str,
            default="/mydata/filesearch_data",
            help="Data directory",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            default="./page_cache_ext_mru.out",
            help="Specify the path to the policy loader binary",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("cgroup_size", [6 * GiB], configs)
        configs = add_config_option(
            "cgroup_name",
            [DEFAULT_BASELINE_CGROUP],
            configs,
            # "cgroup_name", [DEFAULT_CACHE_EXT_CGROUP, DEFAULT_BASELINE_CGROUP], configs
        )
        configs = add_config_option("benchmark", ["kernel_compilation"], configs)
        configs = add_config_option("iteration", [1], configs)

        policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
        for config in configs:
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                config["policy_loader"] = policy_loader_name

        return configs

    def before_benchmark(self, config):
        clean_cmd = ["sudo", "make", "-C", self.args.data_dir, "clean"]
        run(clean_cmd)
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])

            policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
            if policy_loader_name == "cache_ext_s3fifo.out":
                self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
            else:
                self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
        self.start_time = time()

    def benchmark_cmd(self, config):
        data_dir = self.args.data_dir
        script_cmd = f"./bench_script_kernel_compile.sh {data_dir}"
        # compilation_cmd = f"make -C '{data_dir}' -j8"
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            "/bin/sh",
            "-c",
            script_cmd,
        ]
        return cmd

    def after_benchmark(self, config):
        self.end_time = time()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        enable_smt()

        touch_cmd = ["sudo", "touch", f"{self.args.data_dir}/include/linux/mm_types.h"]
        run(touch_cmd)

    def parse_results(self, stdout: str) -> BenchResults:
        results = {"runtime_sec": self.end_time - self.start_time}
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    kernel_comp_benchmark = KernelCompilationBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(kernel_comp_benchmark.args.data_dir):
        raise Exception(
            "Kernel directory not found: %s" % kernel_comp_benchmark.args.data_dir
        )
    log.info("Kernel directory: %s", kernel_comp_benchmark.args.data_dir)
    clean_cmd = ["sudo", "make", "-C", kernel_comp_benchmark.args.data_dir, "clean"]
    run(clean_cmd)
    kernel_comp_benchmark.benchmark()


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
