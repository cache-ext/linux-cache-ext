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
    --results-file ./cache_ext_fio_results.json

# Benchmark LevelDB with mixed GET-SCAN
python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_get_scan.out \
    --results-file ./cache_ext_get_scan_results.json \
    --leveldb-db /mydata/leveldb_db \
    --benchmark mixed_get_scan

# Benchmark LevelDB with LFU
python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_sampling.out \
    --results-file ./cache_ext_lfu_ycsb_results.json \
    --leveldb-db /mydata/leveldb_db \
    --fadvise-hints "" \
    --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_f

# Benchmark Google IO traces
python3 bench_io_trace.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_sampling.out \
    --results-file cache_ext_io_trace_results.json  \
    --trace-temp-data-dir google_traces/data_cluster1_16TB_20240115_app_spanner_temp \
    --trace-data-dir /mydata_2/data_cluster1_16TB_20240115_app_spanner \
    --benchmark trace_cluster1_16TB_20240115_app_spanner

# Benchmark filesearch workload with MRU
python3 bench_filesearch.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_mru.out \
    --results-file ./cache_ext_filesearch_results.json  \
    --data-dir /mydata/filesearch_data
