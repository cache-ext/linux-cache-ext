import logging
import argparse
import papermill as pm


log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser(description="Trace CLI for Google IO traces")
    parser.add_argument(
        "--trace-cluster-name", required=True, type=str, help="Name of the cluster"
    )
    parser.add_argument(
        "--trace-date", type=str, required=True, help="Date of the trace data"
    )
    parser.add_argument(
        "--trace-data_file", type=str, required=True, help="Data file identifier"
    )


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    notebook_path = "trace_explorer.ipynb"
    pm.execute_notebook(
        notebook_path,
        notebook_path,
        parameters=dict(
            trace_cluster_name=args.trace_cluster_name,
            trace_date=args.trace_date,
            trace_data_file=args.trace_data_file,
        ),
    )


if __name__ == "__main__":
    main()
