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
    sudo cgcreate -g memory:mygroup
    sudo sh -c 'echo 1073741824 > /sys/fs/cgroup/mygroup/memory.max'
    ```

1. Enable `page_cache_ext` for the new cgroup.

    ```sh
    echo -n "/mygroup" > /proc/page_cache_ext_enabled_cgroup
    ```

1. Load the extension framework BPF hooks in the kernel.

    ```sh
    make
    sudo ./page_cache_ext_simple.out
    ```

1. Run application with 1.2GB working set.

    ```sh
    cgexec -g memory:mygroup ./test_app.py
    ```

### Teardown

1. Unload the extension framework BPF hooks in the kernel.
1. Disable `page_cache_ext` for cgroup.
1. Destroy cgroup.
