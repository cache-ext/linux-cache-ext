#!/bin/bash

set -e
set -x
set -o pipefail
set -u

# Microbenchmark with fio for CPU overhead
# Assumes the data disk is /dev/sdb
python3 bench_fio.py \
    --cpu 8 \
    --target-file /dev/sdb \
    --results-file ./fio_results.json

# Benchmark LevelDB with LFU
python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_sampling.out \
    --results-file ./lfu_ycsb_results.json
