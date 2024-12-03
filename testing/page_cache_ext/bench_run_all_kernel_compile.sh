#!/bin/bash

set -e
set -x
set -o pipefail
set -u

python3 bench_kernel_compilation.py \
    --cpu 8 \
    --policy-loader ./page_cache_ext_mru.out \
    --results-file ./results/kernel_compile_results.json \
    --data-dir /mydata/cgroup/linuxes/linux \
