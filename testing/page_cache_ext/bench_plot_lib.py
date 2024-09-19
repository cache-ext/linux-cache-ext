#!/usr/bin/env python3

from itertools import groupby
import sys
import json
import logging

from typing import Dict, List, Tuple, Callable
from matplotlib import pyplot as plt
import numpy as np
from bench_lib import BenchRun, BenchResults, DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP


log = logging.getLogger(__name__)


def exists_config_in_results(results: List[BenchRun], config: Dict) -> bool:
    for r in results:
        if r.config == config:
            return True
    return False


def results_select(
    results: List[BenchRun], config_match: Dict, select_fn: Callable
) -> List[BenchRun]:
    # Select results based on partial config match
    return [
        select_fn(r.results)
        for r in results
        if config_match.items() <= r.config.items()
    ]


def single_result_select(
    results: List[BenchRun], config_match: Dict, select_fn: Callable
) -> BenchRun:
    # Select results based on partial config match
    results = results_select(results, config_match, select_fn)
    if len(results) != 1:
        raise ValueError("Expected 1 result, got %s" % results)
    return results[0]


def config_combinations(results: List[BenchRun], fields: List[str]) -> List[Dict]:
    """Get all unique config combinations for the given fields."""
    # Get all unique config combinations
    configs = []
    for r in results:
        if not set(r.config.keys()) >= set(fields):
            continue
        new_combination = {}
        for field in fields:
            new_combination[field] = r.config[field]
        if new_combination not in configs:
            configs.append(new_combination)
    return configs


def filter_lists(l1: List, l2: List, f: callable) -> Tuple[List, List]:
    """Filter two lists based on a filter function."""
    good_idxs = []
    if len(l1) != len(l2):
        raise ValueError("Lists must be of same length")
    for i in range(len(l1)):
        if f(l1[i], l2[i]):
            good_idxs.append(i)
    return [l1[i] for i in good_idxs], [l2[i] for i in good_idxs]


class GrouppedBarPlot(object):
    def __init__(
        self,
        names: List[str],
        y_values: List[List],
        groups: List[str],
        colors: List[str],
        y_label=None,
    ) -> None:
        assert len(names) == len(y_values)
        assert len(y_values) > 0
        self.names = names
        self.y_values = y_values
        self.groups = groups
        self.num_bars = len(y_values)
        self.colors = colors
        self.y_label = y_label


def plot_groupped_bars(
    gpplot: GrouppedBarPlot,
    output="groupped_bars.pdf",
    show_measurements=True,
    measurement_fontsize=10,
    measurement_rotation=0,
    measurement_offset=1000,
    bar_width=0.7,
    ylimit=None,
    hide_y_ticks=False,
    fontsize=12,
    legend_fontsize=12,
    label_fontsize=None,
    legend_loc="best",
):

    if label_fontsize is None:
        label_fontsize = fontsize

    num_bars = gpplot.num_bars
    step = bar_width
    if num_bars % 2 == 0:
        start = -bar_width * (num_bars - 1) / 2
        end = start + bar_width * (num_bars - 1)
        offsets = np.arange(start, end + step, step)
    else:
        start = -bar_width * (num_bars - 1) / 2
        end = start + bar_width * (num_bars - 1)
        offsets = np.arange(start, end + step, step)
    xticks = np.arange(0, 4 * len(gpplot.groups), step=4)
    print(offsets)
    for i in range(num_bars):
        print(xticks + offsets[i])
    for i in range(num_bars):
        plt.bar(
            xticks + offsets[i],
            gpplot.y_values[i],
            width=bar_width,
            label=gpplot.names[i],
            color=gpplot.colors[i],
        )
        if show_measurements:
            for j, v in enumerate(xticks + offsets[i]):
                plt.text(
                    v,
                    gpplot.y_values[i][j] + measurement_offset,
                    str(int(gpplot.y_values[i][j] / 1000)) + "K",
                    ha="center",
                    rotation=measurement_rotation,
                    fontsize=measurement_fontsize,
                    color=gpplot.colors[i],
                    weight="bold",
                )
    plt.xticks(xticks, gpplot.groups, fontsize=fontsize)
    if gpplot.y_label:
        plt.ylabel(gpplot.y_label, fontsize=label_fontsize)
    # plt.xlim(offsets[0] - 4*bar_width, offsets[-1] + 4*bar_width)

    if ylimit:
        plt.ylim(0, ylimit)

    if hide_y_ticks:
        plt.tick_params(axis="y", which="both", labelleft=False)

    plt.yticks(fontsize=fontsize)
    plt.legend(fontsize=legend_fontsize, loc=legend_loc)
    plt.tight_layout()
    plt.savefig(output, metadata={"creationDate": None})
    plt.clf()


def make_name(config: Dict) -> str:
    if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP:
        return "Baseline"
    elif config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
        return "cache_ext"
    return "<unknown>"


def leveldb_plot_ycsb_results(config_matches: List[Dict],
                              results: List[BenchRun],
                              colors=["salmon", "maroon", "peru"],
                              filename="leveldb_ycsb.pdf",
                              name_func=make_name,
                              bench_types=["uniform", "uniform_read_write",
                                           "ycsb_a", "ycsb_b", "ycsb_c",
                                           "ycsb_d", "ycsb_f"],
                              result_select_fn=lambda r: r["throughput_avg"],
                              ylimit=None, hide_y_ticks=False,
                              measurement_rotation=90,
                              measurement_fontsize=12,
                              fontsize=12,
                              legend_fontsize=12,
                              measurement_offset=1000,
                              bar_width=1,
                              group_newline=True,
                              label_fontsize=None,
                              legend_loc='best'):
    """Plot YCSB results for RocksDB.

    Config match dicts should look like this:
        {
            "name": "rocksdb_disk",
            "disk_type": "nvmeof_tcp",
            "cpus": 3,
            "threads_per_core": 10,
            "cache_size": 1000000000,
            "use_bpfof": False,
            "bench_type": "ycsb_a",
        }
    """
    if group_newline:
        bench_type_to_group = {
            "uniform": "Unif.\n(100/0)",
            "uniform_read_write": "Unif.\n(50/50)",
            "ycsb_a": "YCSB\nA",
            "ycsb_b": "YCSB\nB",
            "ycsb_c": "YCSB\nC",
            "ycsb_d": "YCSB\nD",
            "ycsb_f": "YCSB\nF",
            "trace19": "Twitter\n19",
            "trace37": "Twitter\n37",
        }
    else:
        bench_type_to_group = {
            "uniform": "Unif. (100/0)",
            "uniform_read_write": "Unif. (50/50)",
            "ycsb_a": "YCSB A",
            "ycsb_b": "YCSB B",
            "ycsb_c": "YCSB C",
            "ycsb_d": "YCSB D",
            "ycsb_f": "YCSB F",
            "trace19": "Twitter 19",
            "trace37": "Twitter 37",
        }

    groups = [bench_type_to_group[bench_type] for bench_type in bench_types]
    names = []
    y_values = []

    for config_match in config_matches:
        names.append(name_func(config_match))
        ys = []

        for bench_type in bench_types:
            config_match["benchmark"] = bench_type
            y_res = results_select(results, config_match, result_select_fn)
            print(config_match)
            print(y_res)
            assert len(y_res) == 1, "len(y_res) = %d" % len(y_res)
            ys.append(y_res[0])
        assert len(ys) == len(groups), "len(ys) = %d" % len(ys)
        y_values.append(ys)

    print(y_values)
    print(names)

    gpplot = GrouppedBarPlot(names, y_values, groups, colors,
                             y_label="Total Throughput (req/sec)")
    assert gpplot.num_bars == len(colors), "gpplot.num_bars = %d, len(colors) = %d" % (gpplot.num_bars, len(colors))

    plot_groupped_bars(gpplot, filename,
                       measurement_offset=measurement_offset, bar_width=bar_width,
                       measurement_fontsize=measurement_fontsize, measurement_rotation=measurement_rotation,
                       ylimit=ylimit, hide_y_ticks=hide_y_ticks, fontsize=fontsize, legend_fontsize=legend_fontsize,
                       label_fontsize=label_fontsize,
                       legend_loc=legend_loc)
