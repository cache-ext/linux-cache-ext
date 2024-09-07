import json
import subprocess
import time

def run_command():
    cmd = "sudo bpftool map dump name stats"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return json.loads(result.stdout)

def parse_output(data):
    parsed = {}
    for item in data:
        parsed[item['key']] = item['value']
    return parsed

def print_stats(current, previous):
    print(f"scan_pages: {current['scan_pages']}")
    print(f"total_pages: {current['total_pages']}")

    evicted_scan_diff = current['evicted_scan_pages'] - previous.get('evicted_scan_pages', current['evicted_scan_pages'])
    evicted_total_diff = current['evicted_total_pages'] - previous.get('evicted_total_pages', current['evicted_total_pages'])

    print(f"evicted_scan_pages diff: {evicted_scan_diff}")
    print(f"evicted_total_pages diff: {evicted_total_diff}")
    print("---")

def main():
    previous_stats = {}

    while True:
        try:
            output = run_command()
            current_stats = parse_output(output)

            print_stats(current_stats, previous_stats)

            previous_stats = current_stats
            time.sleep(1)  # Wait for 60 seconds before the next iteration
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(3)  # Wait for 60 seconds before retrying

if __name__ == "__main__":
    main()