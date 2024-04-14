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

#include "basic.skel.h"

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

    int ret;
    struct basic_bpf *skel;
    struct bpf_link *link;
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // Open skel
    skel = basic_bpf__open();
    if (skel == NULL) {
        // Check errno for error
        fprintf(stderr, "Failed to open BPF skeleton: %s\n",
                strerror(errno));
        exit(1);
    }
    // Load programs
    ret = basic_bpf__load(skel);
    if (ret) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n",
                strerror(errno));
        basic_bpf__destroy(skel);
        exit(1);
    }
    // Load struct_ops map
    link = bpf_map__attach_cache_ext_ops(skel->maps.simple_ops,cgfd);
    if (link == NULL) {
        fprintf(stderr, "Failed to attach BPF struct_ops map: %s\n",
                strerror(errno));
        basic_bpf__destroy(skel);
        exit(1);
    }

    // Wait for keyboard input
    printf("Press any key to exit...\n");
    getchar();

    // Exit
    bpf_link__destroy(link);
    basic_bpf__destroy(skel);

    return;
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

