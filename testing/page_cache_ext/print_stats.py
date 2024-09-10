import json
import subprocess
import time
import argparse
import logging

log = logging.getLogger(__name__)


def format_bytes_str(bytes: int):
    if bytes < 1024:
        return f"{bytes} B"
    elif bytes < 1024**2:
        return f"{bytes / 1024:.1f} KiB"
    elif bytes < 1024**3:
        return f"{bytes / 1024**2:.1f} MiB"
    else:
        return f"{bytes / 1024**3:.1f} GiB"


def parse_output(data):
    parsed = {}
    for item in data:
        parsed[item['key']] = item['value']
    return parsed


def print_bpf_stats(current, previous):
    print(f"scan_pages: {current['scan_pages']}")
    print(f"total_pages: {current['total_pages']}")

    evicted_scan_diff = current['evicted_scan_pages'] - previous.get('evicted_scan_pages', current['evicted_scan_pages'])
    evicted_total_diff = current['evicted_total_pages'] - previous.get('evicted_total_pages', current['evicted_total_pages'])

    print(f"evicted_scan_pages diff: {evicted_scan_diff}")
    print(f"evicted_total_pages diff: {evicted_total_diff}")
    print("---")


def print_cgroup_stats(current, previous):
    # Print file, active_file, inactive_file
    file_bytes = current["file"]
    active_file_bytes = current["active_file"]
    inactive_file_bytes = current["inactive_file"]

    print(f"File: {format_bytes_str(file_bytes)}")
    print(f"Active File: {format_bytes_str(active_file_bytes)}")
    print(f"Inactive File: {format_bytes_str(inactive_file_bytes)}")
    print("---")


def parse_args():
    parser = argparse.ArgumentParser(description="Print cgroup and BPF stats")
    parser.add_argument("--cgroup", type=str, default="cache_ext_test",
                        help="Name of the cgroup to monitor (default: cache_ext_test)")
    return parser.parse_args()

def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    previous_cgroup_stats = {}
    previous_bpf_stats = {}

    cgroup = args.cgroup
    log.info(f"Monitoring cgroup: {cgroup}")

    while True:
        try:
            # Cgroup Memory stats
            mem_stat_file = f"/sys/fs/cgroup/{cgroup}/memory.stat"
            with open(mem_stat_file, "r") as f:
                data = f.readlines()
                current_cgroup_stats = {line.split()[0]: int(line.split()[1]) for line in data}
            print_cgroup_stats(current_cgroup_stats, previous_cgroup_stats)
            previous_cgroup_stats = current_cgroup_stats

            # BPF stats
            cmd = "sudo bpftool map dump name stats"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = json.loads(result.stdout)
            current_bpf_stats = parse_output(output)

            print_bpf_stats(current_bpf_stats, previous_bpf_stats)

            previous_bpf_stats = current_bpf_stats
            time.sleep(1)  # Wait for 60 seconds before the next iteration
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(3)  # Wait for 60 seconds before retrying

if __name__ == "__main__":
    main()