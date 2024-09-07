# Page Cache Ext

`page_cache_ext` is a page cache extension framework for the Linux Kernel page
cache. Roughly, it allows offloading page cache management to userspace and BPF.


## Architecture

The current architecture is the following:
- `page_cache_ext` can be active for a single cgroup only.
- Only eviction is supported.

## Install dependencies

1. Install libbpf:

    ```sh
    cd tools/bpf
    make -j$(nproc)
    sudo make install
    ```

1. Install bpftool:

    ```sh
    cd tools/bpf/bpftool
    make -j$(nproc)
    sudo make install
    sudo cp bpftool /usr/bin
    ```

## Demo

### Setup

1. Create a new memory cgroup with 1GB limit for the demo.

    ```sh
    sudo cgcreate -g memory:cache_ext_test
    sudo sh -c 'echo 1073741824 > /sys/fs/cgroup/cache_ext_test/memory.max'
    ```

1. Enable `page_cache_ext` for the new cgroup.

    ```sh
    echo -n "/cache_ext_test" > /proc/page_cache_ext_enabled_cgroup
    ```

1. Load the extension framework BPF hooks in the kernel.

    ```sh
    make
    sudo ./page_cache_ext_simple.out
    ```

1. Run application with 1.2GB working set.

    ```sh
    time sudo cgexec -g memory:cache_ext_test ./test_app.py --iterations 4
    ```

### Teardown

1. Unload the extension framework BPF hooks in the kernel.
1. Disable `page_cache_ext` for cgroup.
1. Destroy cgroup.


### Comparative test with baseline cgroup

1. Create a new memory cgroup with 1GB limit for the demo.

    ```sh
    sudo cgcreate -g memory:baseline_test
    sudo sh -c 'echo 1073741824 > /sys/fs/cgroup/baseline_test/memory.max'
    ```

## LevelDB

### Create database

```sh
# Install rclone
sudo apt-get install rclone

# Setup rclone
rclone config

# Clone the db
rclone sync --progress --transfers $(nproc) --checkers $(nproc) b2:leveldb /mydata/leveldb_db

# Use a copy for testing
rsync -avpl --delete /mydata/leveldb_db/ /mydata/leveldb_db_temp
```

### Test LevelDB

1. Create a new memory cgroup with 5GB limit for the demo.

    ```sh
    sudo cgcreate -g memory:cache_ext_test
    sudo sh -c 'echo 2147483648 > /sys/fs/cgroup/cache_ext_test/memory.max'
    ```

1. Enable `page_cache_ext` for the new cgroup.

    ```sh
    echo -n "/cache_ext_test" > /proc/page_cache_ext_enabled_cgroup
    ```

1. Run LevelDB:

    ```sh
    cd /mydata/My-YCSB/build
    sudo cgexec -g memory:cache_ext_test ./run_leveldb ../leveldb/config/ycsb_a.yaml
    ```
