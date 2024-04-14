#!/bin/bash

cgcreate -g memory:cache_ext_1
sh -c 'echo 107374182 > /sys/fs/cgroup/cache_ext_1/memory.max'

cgcreate -g memory:cache_ext_2
sh -c 'echo 107374182 > /sys/fs/cgroup/cache_ext_2/memory.max'

echo "Starting bpf program..."

LD_LIBRARY_PATH=/mydata/linux-cachestream/tools/lib/bpf/ ./cgroup_cache_ext.out
