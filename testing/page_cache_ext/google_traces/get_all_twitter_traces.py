import logging
import argparse

from tqdm import tqdm
from multiprocessing import Pool
from yanniszark_common.cmdutils import check_output


log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Download all twitter traces and prep for LevelDB benchmarking"
    )
    return parser.parse_args()


def download_and_create_trace(cluster_name: str):
    notebook_path = "trace_explorer_twitter.ipynb"
    cmd = [
        "papermill",
        notebook_path,
        "-",
        "-p",
        "cluster_name",
        cluster_name,
        "-p",
        "num_rows_to_keep",
        "60000000",
        "-p",
        "delete_trace_file",
        "True",
        "-p",
        "force",
        "True",
    ]
    log.info("Running papermill command: %s", " ".join(cmd))
    out = check_output(cmd)
    logfile = f"twitter_{cluster_name}_papermill.log"
    with open(logfile, "w") as f:
        f.write(out)
    log.info("Papermill output written to %s", logfile)


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    # Download traces in parallel using multiprocessing

    clusters = []
    done_clusters = [1, 2, 13, 14, 17, 18, 24, 34, 45, 52] + list(range(3, 12+1))
    for i in range(1, 54 + 1):
        if i in done_clusters:
            log.info("Skipping cluster %d", i)
            continue
        clusters.append(f"cluster{i}")

    with Pool(processes=2) as pool:
        # Map the download function across clusters with progress bar
        for _ in tqdm(
            pool.imap_unordered(download_and_create_trace, clusters),
            total=len(clusters),
            desc="Downloading traces",
        ):
            pass


if __name__ == "__main__":
    main()
