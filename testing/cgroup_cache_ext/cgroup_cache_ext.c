#include <bpf/libbpf_legacy.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define CGROUP_1 "/sys/fs/cgroup/cache_ext_1/"
#define CGROUP_2 "/sys/fs/cgroup/cache_ext_2/"
#define PATH_MAX 1024

void attach_map_to_cgroup(char *cg) {
    struct bpf_object *obj;
    struct bpf_map *map;
    int cgfd = open(cg, O_RDONLY);
    if (cgfd < 0) {
        perror("cgfd");
        exit(1);
    }

    // Load and verify BPF application
    obj = bpf_object__open_file("basic.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        goto out1;
    }

    map = bpf_object__next_map(obj, NULL);
    if (!map) {
        perror("Failed to attach DEV_CGROUP program");
        goto out;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF program failed\n");
        goto out;
    }

    /* Attach bpf program */
    if (bpf_map__attach_cache_ext_ops(map, cgfd)) {
        perror("Failed to attach DEV_CGROUP program");
        goto out;
    }

    return;

out:
    bpf_object__close(obj);
out1:
    close(cgfd);
    exit(1);
}

int main() {
    char cgroup_path[PATH_MAX-13];
    char cgroup_procs_path[PATH_MAX];
    struct bpf_object *obj;
    struct bpf_program *prog;
    int fd_procs, cgroup_fd, prog_fd;

    pid_t p = fork();
    if (p < 0) {
        perror("fork");
        exit(1);
    }

    if (p > 0) {
        attach_map_to_cgroup(CGROUP_1);
    } else {
        attach_map_to_cgroup(CGROUP_2);
    }
}

