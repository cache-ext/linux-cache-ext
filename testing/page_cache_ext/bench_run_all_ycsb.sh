#!/bin/bash

set -e
set -x
set -o pipefail
set -u

python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./cache_ext_lhd.out \
    --results-file ./cache_ext_ycsb_results.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --fadvise-hints "" \
    --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_f

python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./cache_ext_s3fifo.out \
    --results-file ./cache_ext_ycsb_results.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --fadvise-hints "" \
    --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_f

python3 bench_leveldb.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_sampling.out \
    --results-file ./cache_ext_ycsb_results.json \
    --leveldb-db /mydata/leveldb_myycsb_db \
    --fadvise-hints "" \
    --benchmark ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_f
